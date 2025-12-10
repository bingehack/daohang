// src/api/http.ts
// 不使用外部JWT库，改为内置的crypto API
import { compareSync } from 'bcrypt-edge';

// 定义D1数据库类型
interface D1Database {
  prepare(query: string): D1PreparedStatement;
  exec(query: string): Promise<D1Result>;
  batch<T = unknown>(statements: D1PreparedStatement[]): Promise<D1Result<T>[]>;
}

interface D1PreparedStatement {
  bind(...values: unknown[]): D1PreparedStatement;
  first<T = unknown>(column?: string): Promise<T | null>;
  run<T = unknown>(): Promise<D1Result<T>>;
  all<T = unknown>(): Promise<D1Result<T>>;
}

interface D1Result<T = unknown> {
  results?: T[];
  success: boolean;
  error?: string;
  meta?: unknown;
}

// 定义环境变量接口
interface Env {
  DB: D1Database;
  AUTH_ENABLED?: string; // 是否启用身份验证
  AUTH_USERNAME?: string; // 认证用户名
  AUTH_PASSWORD?: string; // 认证密码哈希 (bcrypt)
  AUTH_SECRET?: string; // JWT密钥
}

// 数据类型定义
export interface Group {
  id?: number;
  name: string;
  parent_id?: number | null; // 添加父分类ID，支持层级结构
  order_num: number;
  is_public?: number; // 0 = 私密（仅管理员可见），1 = 公开（访客可见）
  created_at?: string;
  updated_at?: string;
}

export interface Site {
  id?: number;
  group_id: number;
  name: string;
  url: string;
  icon: string;
  description: string;
  notes: string;
  order_num: number;
  is_public?: number; // 0 = 私密（仅管理员可见），1 = 公开（访客可见）
  created_at?: string;
  updated_at?: string;
}

// 分组及其站点 (用于优化 N+1 查询)
export interface GroupWithSites extends Group {
  id: number; // 确保 id 存在
  sites: Site[];
}

// 新增配置接口
export interface Config {
  key: string;
  value: string;
  created_at?: string;
  updated_at?: string;
}

// 扩展导出数据接口，添加导入结果类型
export interface ExportData {
  groups: Group[];
  sites: Site[];
  configs: Record<string, string>;
  version: string;
  exportDate: string;
}

// 导入结果接口
export interface ImportResult {
  success: boolean;
  stats?: {
    groups: {
      total: number;
      created: number;
      merged: number;
    };
    sites: {
      total: number;
      created: number;
      updated: number;
      skipped: number;
    };
  };
  error?: string;
}

// 新增用户登录接口
export interface LoginRequest {
  username: string;
  password: string;
  rememberMe?: boolean; // 新增记住我选项
}

export interface LoginResponse {
  success: boolean;
  token?: string;
  message?: string;
}

// API 类
export class NavigationAPI {
  private db: D1Database;
  private authEnabled: boolean;
  private username: string;
  private passwordHash: string; // 存储bcrypt哈希而非明文密码
  private secret: string;

  constructor(env: Env) {
    this.db = env.DB;
    this.authEnabled = env.AUTH_ENABLED === 'true';
    this.username = env.AUTH_USERNAME || '';
    this.passwordHash = env.AUTH_PASSWORD || ''; // 现在存储的是哈希
    this.secret = env.AUTH_SECRET || 'DefaultSecretKey';
  }

  // 初始化数据库表
  // 修改initDB方法，将SQL语句分开执行
  async initDB(): Promise<{ success: boolean; alreadyInitialized: boolean }> {
    // 首先检查数据库是否已初始化
    try {
      const isInitialized = await this.getConfig('DB_INITIALIZED');
      if (isInitialized === 'true') {
        return { success: true, alreadyInitialized: true };
      }
    } catch {
      // 如果发生错误，可能是配置表不存在，继续初始化
    }

    // 先创建groups表
    await this.db.exec(
      `CREATE TABLE IF NOT EXISTS groups (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, order_num INTEGER NOT NULL, parent_id INTEGER DEFAULT NULL, is_public INTEGER DEFAULT 1, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (parent_id) REFERENCES groups(id) ON DELETE CASCADE);`
    );

    // 再创建sites表
    await this.db.exec(
      `CREATE TABLE IF NOT EXISTS sites (id INTEGER PRIMARY KEY AUTOINCREMENT, group_id INTEGER NOT NULL, name TEXT NOT NULL, url TEXT NOT NULL, icon TEXT, description TEXT, notes TEXT, order_num INTEGER NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE);`
    );

    // 创建全局配置表
    await this.db.exec(`CREATE TABLE IF NOT EXISTS configs (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );`);

    // 设置初始化标志
    await this.setConfig('DB_INITIALIZED', 'true');

    return { success: true, alreadyInitialized: false };
  }

  // 验证用户登录
  async login(loginRequest: LoginRequest): Promise<LoginResponse> {
    // 如果未启用身份验证，直接返回成功
    if (!this.authEnabled) {
      return {
        success: true,
        token: await this.generateToken({ username: 'guest' }, false),
        message: '身份验证未启用，默认登录成功',
      };
    }

    // 验证用户名
    if (loginRequest.username !== this.username) {
      return {
        success: false,
        message: '用户名或密码错误',
      };
    }

    // 使用 bcrypt 验证密码
    const isPasswordValid = compareSync(loginRequest.password, this.passwordHash);

    if (isPasswordValid) {
      // 生成JWT令牌，传递记住我参数
      const token = await this.generateToken(
        { username: loginRequest.username },
        loginRequest.rememberMe || false
      );
      return {
        success: true,
        token,
        message: '登录成功',
      };
    }

    return {
      success: false,
      message: '用户名或密码错误',
    };
  }

  // 验证令牌有效性
  async verifyToken(token: string): Promise<{ valid: boolean; payload?: Record<string, unknown> }> {
    if (!this.authEnabled) {
      return { valid: true };
    }

    try {
      // 解析JWT
      const parts = token.split('.');
      if (parts.length !== 3) {
        return { valid: false };
      }

      const [encodedHeader, encodedPayload, signature] = parts;

      // Validate all parts exist
      if (!encodedHeader || !encodedPayload || !signature) {
        return { valid: false };
      }

      // 重新生成签名进行验证
      const encoder = new TextEncoder();
      const data = encoder.encode(`${encodedHeader}.${encodedPayload}`);
      const keyData = encoder.encode(this.secret);

      // 导入密钥
      const key = await crypto.subtle.importKey(
        'raw',
        keyData,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['verify']
      );

      // 解码签名
      const signatureBytes = this.base64UrlDecode(signature);

      // 验证签名
      const isValid = await crypto.subtle.verify('HMAC', key, signatureBytes, data);

      if (!isValid) {
        return { valid: false };
      }

      // 解码并验证 payload
      const payloadStr = atob(encodedPayload.replace(/-/g, '+').replace(/_/g, '/'));
      const payload = JSON.parse(payloadStr) as Record<string, unknown>;

      // 检查过期时间
      const now = Math.floor(Date.now() / 1000);
      if (payload.exp && typeof payload.exp === 'number' && payload.exp < now) {
        return { valid: false };
      }

      return { valid: true, payload };
    } catch (error) {
      console.error('Token验证失败:', error);
      return { valid: false };
    }
  }

  // 生成JWT令牌
  private async generateToken(
    payload: Record<string, unknown>,
    rememberMe: boolean = false
  ): Promise<string> {
    // 准备payload
    const expiresIn = rememberMe
      ? 30 * 24 * 60 * 60 // 30天 (一个月)
      : 24 * 60 * 60; // 24小时

    const tokenPayload = {
      ...payload,
      exp: Math.floor(Date.now() / 1000) + expiresIn,
      iat: Math.floor(Date.now() / 1000),
    };

    // 创建Header和Payload部分
    const header = { alg: 'HS256', typ: 'JWT' };
    const encodedHeader = this.base64UrlEncode(JSON.stringify(header));
    const encodedPayload = this.base64UrlEncode(JSON.stringify(tokenPayload));

    // 使用 Web Crypto API 进行 HMAC-SHA256 签名
    const encoder = new TextEncoder();
    const data = encoder.encode(`${encodedHeader}.${encodedPayload}`);
    const keyData = encoder.encode(this.secret);

    // 导入密钥
    const key = await crypto.subtle.importKey(
      'raw',
      keyData,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );

    // 生成签名
    const signatureBuffer = await crypto.subtle.sign('HMAC', key, data);
    const signature = this.base64UrlEncode(signatureBuffer);

    // 组合JWT
    return `${encodedHeader}.${encodedPayload}.${signature}`;
  }

  // 辅助方法：base64url 编码（支持字符串和 ArrayBuffer）
  private base64UrlEncode(data: string | ArrayBuffer): string {
    let base64: string;

    if (typeof data === 'string') {
      base64 = btoa(data);
    } else {
      // ArrayBuffer 转 base64
      const bytes = new Uint8Array(data);
      const binary = Array.from(bytes)
        .map((byte) => String.fromCharCode(byte))
        .join('');
      base64 = btoa(binary);
    }

    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  // 辅助方法：base64url 解码为 ArrayBuffer
  private base64UrlDecode(base64url: string): ArrayBuffer {
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const padding = '='.repeat((4 - (base64.length % 4)) % 4);
    const binary = atob(base64 + padding);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  // 检查认证是否启用
  isAuthEnabled(): boolean {
    return this.authEnabled;
  }

  // 分组相关 API
  async getGroups(): Promise<Group[]> {
    const result = await this.db
      .prepare('SELECT id, name, order_num, parent_id, is_public, created_at, updated_at FROM groups ORDER BY parent_id, order_num')
      .all<Group>();
    return result.results || [];
  }

  async getGroup(id: number): Promise<Group | null> {
    const result = await this.db
      .prepare('SELECT id, name, order_num, parent_id, is_public, created_at, updated_at FROM groups WHERE id = ?')
      .bind(id)
      .first<Group>();
    return result;
  }

  async createGroup(group: Group): Promise<Group> {
    const result = await this.db
      .prepare(
        'INSERT INTO groups (name, order_num, parent_id, is_public) VALUES (?, ?, ?, ?) RETURNING id, name, order_num, parent_id, is_public, created_at, updated_at'
      )
      .bind(group.name, group.order_num, group.parent_id ?? null, group.is_public ?? 1)
      .all<Group>();
    if (!result.results || result.results.length === 0) {
      throw new Error('创建分组失败');
    }
    const createdGroup = result.results[0];
    if (!createdGroup) {
      throw new Error('创建分组失败');
    }
    return createdGroup;
  }

  async updateGroup(id: number, group: Partial<Group>): Promise<Group | null> {
    // 字段白名单
    const ALLOWED_FIELDS = ['name', 'order_num', 'parent_id', 'is_public'] as const;
    type AllowedField = (typeof ALLOWED_FIELDS)[number];

    const updates: string[] = ['updated_at = CURRENT_TIMESTAMP'];
    const params: (string | number)[] = [];

    // 只允许更新白名单中的字段
    Object.entries(group).forEach(([key, value]) => {
      if (ALLOWED_FIELDS.includes(key as AllowedField) && value !== undefined && value !== null) {
        updates.push(`${key} = ?`);
        params.push(value);
      } else if (ALLOWED_FIELDS.includes(key as AllowedField) && value === null) {
        updates.push(`${key} = NULL`);
        // 对于NULL值，不需要添加到params中
      } else if (key !== 'id' && key !== 'created_at' && key !== 'updated_at') {
        console.warn(`尝试更新不允许的字段: ${key}`);
      }
    });

    if (updates.length === 1) {
      // 只有 updated_at，没有实际更新
      throw new Error('没有可更新的字段');
    }

    // 构建安全的参数化查询
    const query = `UPDATE groups SET ${updates.join(
      ', '
    )} WHERE id = ? RETURNING id, name, order_num, created_at, updated_at`;
    params.push(id);

    const result = await this.db
      .prepare(query)
      .bind(...params)
      .all<Group>();

    if (!result.results || result.results.length === 0) {
      return null;
    }
    const updatedGroup = result.results[0];
    return updatedGroup || null;
  }

  async deleteGroup(id: number): Promise<boolean> {
    const result = await this.db.prepare('DELETE FROM groups WHERE id = ?').bind(id).run();
    return result.success;
  }

  // 网站相关 API
  async getSites(groupId?: number): Promise<Site[]> {
    let query =
      'SELECT id, group_id, name, url, icon, description, notes, order_num, created_at, updated_at FROM sites';
    const params: (string | number)[] = [];

    if (groupId !== undefined) {
      query += ' WHERE group_id = ?';
      params.push(groupId);
    }

    query += ' ORDER BY order_num';

    const result = await this.db
      .prepare(query)
      .bind(...params)
      .all<Site>();
    return result.results || [];
  }

  /**
   * 获取所有分组及其站点 (使用 JOIN 优化,避免 N+1 查询)
   * 返回格式: GroupWithSites[] (每个分组包含其站点数组)
   */
  async getGroupsWithSites(): Promise<GroupWithSites[]> {
    // 使用 LEFT JOIN 一次性获取所有数据
    const query = `
      SELECT
        g.id as group_id,
        g.name as group_name,
        g.parent_id as group_parent_id,
        g.order_num as group_order,
        g.is_public as group_is_public,
        g.created_at as group_created_at,
        g.updated_at as group_updated_at,
        s.id as site_id,
        s.name as site_name,
        s.url as site_url,
        s.icon as site_icon,
        s.description as site_description,
        s.notes as site_notes,
        s.order_num as site_order,
        s.is_public as site_is_public,
        s.created_at as site_created_at,
        s.updated_at as site_updated_at
      FROM groups g
      LEFT JOIN sites s ON g.id = s.group_id
      ORDER BY g.parent_id ASC, g.order_num ASC, s.order_num ASC
    `;

    const result = await this.db.prepare(query).all<{
      group_id: number;
      group_name: string;
      group_parent_id?: number | null;
      group_order: number;
      group_is_public?: number;
      group_created_at: string;
      group_updated_at: string;
      site_id: number | null;
      site_name: string | null;
      site_url: string | null;
      site_icon: string | null;
      site_description: string | null;
      site_notes: string | null;
      site_order: number | null;
      site_is_public?: number;
      site_created_at: string | null;
      site_updated_at: string | null;
    }>();

    // 将查询结果转换为 GroupWithSites 格式
    const groupsMap = new Map<number, GroupWithSites & { subgroups?: GroupWithSites[] }>();

    for (const row of result.results || []) {
      // 如果分组不存在,创建它
      if (!groupsMap.has(row.group_id)) {
        groupsMap.set(row.group_id, {
          id: row.group_id,
          name: row.group_name,
          parent_id: row.group_parent_id || null,
          order_num: row.group_order,
          is_public: row.group_is_public,
          created_at: row.group_created_at,
          updated_at: row.group_updated_at,
          sites: [],
          subgroups: [],
        });
      }

      // 如果有站点数据,添加到分组的 sites 数组
      if (row.site_id !== null) {
        const group = groupsMap.get(row.group_id)!;
        group.sites.push({
          id: row.site_id,
          group_id: row.group_id,
          name: row.site_name!,
          url: row.site_url!,
          icon: row.site_icon || '',
          description: row.site_description || '',
          notes: row.site_notes || '',
          order_num: row.site_order!,
          is_public: row.site_is_public,
          created_at: row.site_created_at!,
          updated_at: row.site_updated_at!,
        });
      }
    }

    // 构建层级结构
    const rootGroups: (GroupWithSites & { subgroups?: GroupWithSites[] })[] = [];
    
    for (const group of groupsMap.values()) {
      if (group.parent_id === null || group.parent_id === undefined) {
        // 根分组（大分类）
        rootGroups.push(group);
      } else {
        // 子分组（小分类）
        const parentGroup = groupsMap.get(group.parent_id);
        if (parentGroup) {
          if (!parentGroup.subgroups) {
            parentGroup.subgroups = [];
          }
          parentGroup.subgroups.push(group as GroupWithSites);
        } else {
          // 如果父分组不存在，将其作为根分组处理
          rootGroups.push(group);
        }
      }
    }

    // 移除临时添加的 subgroups 属性，确保返回类型正确
    return rootGroups.map(group => {
      const { subgroups, ...groupWithoutSubgroups } = group;
      return groupWithoutSubgroups;
    });
  }

  async getSite(id: number): Promise<Site | null> {
    const result = await this.db
      .prepare(
        'SELECT id, group_id, name, url, icon, description, notes, order_num, created_at, updated_at FROM sites WHERE id = ?'
      )
      .bind(id)
      .first<Site>();
    return result;
  }

  async createSite(site: Site): Promise<Site> {
    const result = await this.db
      .prepare(
        `
      INSERT INTO sites (group_id, name, url, icon, description, notes, order_num, is_public)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      RETURNING id, group_id, name, url, icon, description, notes, order_num, is_public, created_at, updated_at
    `
      )
      .bind(
        site.group_id,
        site.name,
        site.url,
        site.icon || '',
        site.description || '',
        site.notes || '',
        site.order_num,
        site.is_public ?? 1
      )
      .all<Site>();

    if (!result.results || result.results.length === 0) {
      throw new Error('创建站点失败');
    }
    const createdSite = result.results[0];
    if (!createdSite) {
      throw new Error('创建站点失败');
    }
    return createdSite;
  }

  async updateSite(id: number, site: Partial<Site>): Promise<Site | null> {
    // 字段白名单
    const ALLOWED_FIELDS = [
      'group_id',
      'name',
      'url',
      'icon',
      'description',
      'notes',
      'order_num',
      'is_public',
    ] as const;
    type AllowedField = (typeof ALLOWED_FIELDS)[number];

    const updates: string[] = ['updated_at = CURRENT_TIMESTAMP'];
    const params: (string | number)[] = [];

    // 只允许更新白名单中的字段
    Object.entries(site).forEach(([key, value]) => {
      if (ALLOWED_FIELDS.includes(key as AllowedField) && value !== undefined) {
        updates.push(`${key} = ?`);
        params.push(value);
      } else if (key !== 'id' && key !== 'created_at' && key !== 'updated_at') {
        console.warn(`尝试更新不允许的字段: ${key}`);
      }
    });

    if (updates.length === 1) {
      // 只有 updated_at，没有实际更新
      throw new Error('没有可更新的字段');
    }

    // 构建安全的参数化查询
    const query = `UPDATE sites SET ${updates.join(
      ', '
    )} WHERE id = ? RETURNING id, group_id, name, url, icon, description, notes, order_num, created_at, updated_at`;
    params.push(id);

    const result = await this.db
      .prepare(query)
      .bind(...params)
      .all<Site>();

    if (!result.results || result.results.length === 0) {
      return null;
    }
    const updatedSite = result.results[0];
    return updatedSite || null;
  }

  async deleteSite(id: number): Promise<boolean> {
    const result = await this.db.prepare('DELETE FROM sites WHERE id = ?').bind(id).run();
    return result.success;
  }

  // 配置相关API
  async getConfigs(): Promise<Record<string, string>> {
    const result = await this.db.prepare('SELECT key, value FROM configs').all<Config>();

    // 将结果转换为键值对对象
    const configs: Record<string, string> = {};
    for (const config of result.results || []) {
      configs[config.key] = config.value;
    }

    return configs;
  }

  async getConfig(key: string): Promise<string | null> {
    const result = await this.db
      .prepare('SELECT value FROM configs WHERE key = ?')
      .bind(key)
      .first<{ value: string }>();

    return result ? result.value : null;
  }

  async setConfig(key: string, value: string): Promise<boolean> {
    try {
      // 使用UPSERT语法（SQLite支持）
      const result = await this.db
        .prepare(
          `INSERT INTO configs (key, value, updated_at) 
                    VALUES (?, ?, CURRENT_TIMESTAMP) 
                    ON CONFLICT(key) 
                    DO UPDATE SET value = ?, updated_at = CURRENT_TIMESTAMP`
        )
        .bind(key, value, value)
        .run();

      return result.success;
    } catch (error) {
      console.error('设置配置失败:', error);
      return false;
    }
  }

  async deleteConfig(key: string): Promise<boolean> {
    const result = await this.db.prepare('DELETE FROM configs WHERE key = ?').bind(key).run();

    return result.success;
  }

  // 批量更新排序
  async updateGroupOrder(groupOrders: { id: number; order_num: number }[]): Promise<boolean> {
    // 使用事务确保所有更新一起成功或失败
    return await this.db
      .batch(
        groupOrders.map((item) =>
          this.db
            .prepare('UPDATE groups SET order_num = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?')
            .bind(item.order_num, item.id)
        )
      )
      .then(() => true)
      .catch(() => false);
  }

  async updateSiteOrder(siteOrders: { id: number; order_num: number }[]): Promise<boolean> {
    // 使用事务确保所有更新一起成功或失败
    return await this.db
      .batch(
        siteOrders.map((item) =>
          this.db
            .prepare('UPDATE sites SET order_num = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?')
            .bind(item.order_num, item.id)
        )
      )
      .then(() => true)
      .catch(() => false);
  }

  // 导出所有数据
  async exportData(): Promise<ExportData> {
    // 获取所有分组
    const groups = await this.getGroups();

    // 获取所有站点
    const sites = await this.getSites();

    // 获取所有配置
    const configs = await this.getConfigs();

    return {
      groups,
      sites,
      configs,
      version: '1.0', // 数据版本号，便于后续兼容性处理
      exportDate: new Date().toISOString(),
    };
  }

  // 导入所有数据
  async importData(data: ExportData): Promise<ImportResult> {
    try {
      // 统计信息
      const stats = {
        groups: {
          total: data.groups.length,
          created: 0,
          merged: 0,
        },
        sites: {
          total: data.sites.length,
          created: 0,
          updated: 0,
          skipped: 0,
        },
      };

      // 批量导入策略：
      // 1. 先获取所有现有分组名称和站点URL，避免重复查询
      // 2. 创建分组ID映射，确保层级关系正确
      // 3. 按层级顺序导入分组，确保子分组能找到父分组
      // 4. 使用batch方法批量处理创建和更新操作

      // 获取所有现有分组
      const existingGroupsResult = await this.db
        .prepare('SELECT id, name FROM groups')
        .all<{ id: number; name: string }>();
      const existingGroups = new Map(existingGroupsResult.results?.map(g => [g.name, g.id]) || []);

      // 获取所有现有站点（按分组ID和URL索引）
      const existingSitesResult = await this.db
        .prepare('SELECT id, group_id, url FROM sites')
        .all<{ id: number; group_id: number; url: string }>();
      const existingSites = new Map(
        existingSitesResult.results?.map(s => [`${s.group_id}:${s.url}`, s.id]) || []
      );

      // 创建新旧分组ID的映射
      const groupMap = new Map<number, number>();
      const batchStatements: D1PreparedStatement[] = [];

      // 按层级处理分组：先处理根分组，再处理一级子分组，以此类推
      const processGroupsByLevel = async () => {
        // 查找根分组（没有父ID的分组）
        const rootGroups = data.groups.filter(group => !group.parent_id || group.parent_id === null);
        const processedGroups = new Set<number>();
        let level = 0;
        let hasMoreGroups = true;

        while (hasMoreGroups && level < 10) { // 最多处理10级深度，防止无限循环
          let levelGroups;
          
          if (level === 0) {
            levelGroups = rootGroups;
          } else {
            // 找到所有父ID已处理的子分组
            levelGroups = data.groups.filter(group => 
              group.parent_id && 
              group.parent_id !== null && 
              groupMap.has(group.parent_id) && 
              group.id !== undefined && 
              !processedGroups.has(group.id)
            );
          }

          if (levelGroups.length === 0) {
            hasMoreGroups = false;
            continue;
          }

          // 处理当前层级的分组
          for (const group of levelGroups) {
            const parentId = level === 0 ? null : groupMap.get(group.parent_id!);
            
            if (existingGroups.has(group.name)) {
              // 如果存在同名分组，使用现有分组ID
              const existingId = existingGroups.get(group.name) as number;
              if (group.id) {
                groupMap.set(group.id, existingId);
              }
              stats.groups.merged++;
            } else {
              // 如果不存在同名分组，创建新分组（使用batch）
              const stmt = this.db
                .prepare('INSERT INTO groups (name, parent_id, order_num, is_public) VALUES (?, ?, ?, ?)')
                .bind(group.name, parentId, group.order_num, group.is_public || 1);
              batchStatements.push(stmt);
              stats.groups.created++;
            }
            
            // 确保group.id是number类型
            if (group.id) {
              processedGroups.add(group.id);
            }
          }

          // 执行当前层级的分组创建
          if (batchStatements.length > 0) {
            await this.db.batch(batchStatements);
            batchStatements.length = 0; // 清空批次

            // 获取最新的分组信息，包含新创建的分组
            const updatedGroupsResult = await this.db
              .prepare('SELECT id, name FROM groups')
              .all<{ id: number; name: string }>();
            const updatedGroups = new Map(updatedGroupsResult.results?.map(g => [g.name, g.id]) || []);

            // 更新分组ID映射（对于新创建的分组）
            for (const group of levelGroups) {
              if (!existingGroups.has(group.name) && group.id) {
                const newId = updatedGroups.get(group.name);
                if (newId) {
                  groupMap.set(group.id, newId);
                }
              }
              
              // 确保group.id是number类型
              if (group.id) {
                processedGroups.add(group.id);
              }
            }
          }

          level++;
        }

        // 检查是否有未处理的分组
        const unprocessedGroups = data.groups.filter(group => group.id && !processedGroups.has(group.id));
        if (unprocessedGroups.length > 0) {
          console.warn(`未处理的分组：${unprocessedGroups.map(g => g.name).join(', ')}`);
        }
      };

      // 按层级处理所有分组
      await processGroupsByLevel();

      // 3. 批量处理站点
      for (const site of data.sites) {
        // 获取新的分组ID
        const newGroupId = groupMap.get(site.group_id);

        // 如果没有映射到新ID（可能是因为分组被过滤掉），则跳过该站点
        if (!newGroupId) {
          console.warn(`无法为站点"${site.name}"找到对应的分组ID，已跳过`);
          stats.sites.skipped++;
          continue;
        }

        const siteKey = `${newGroupId}:${site.url}`;

        if (existingSites.has(siteKey)) {
          // 如果存在相同URL的站点，更新信息
          const siteId = existingSites.get(siteKey) as number;
          const stmt = this.db
            .prepare('UPDATE sites SET name = ?, icon = ?, description = ?, notes = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?')
            .bind(site.name, site.icon, site.description, site.notes, siteId);
          batchStatements.push(stmt);
          stats.sites.updated++;
        } else {
          // 如果不存在相同URL的站点，创建新站点
          const stmt = this.db
            .prepare('INSERT INTO sites (group_id, name, url, icon, description, notes, order_num, is_public) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
            .bind(newGroupId, site.name, site.url, site.icon, site.description, site.notes, site.order_num, site.is_public || 1);
          batchStatements.push(stmt);
          stats.sites.created++;
        }
      }

      // 执行站点批量操作
      if (batchStatements.length > 0) {
        await this.db.batch(batchStatements);
        batchStatements.length = 0; // 清空批次
      }

      // 4. 批量处理配置数据
      for (const [key, value] of Object.entries(data.configs)) {
        if (key !== 'DB_INITIALIZED') {
          // 使用INSERT OR REPLACE来处理配置
          const stmt = this.db
            .prepare('INSERT OR REPLACE INTO configs (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)')
            .bind(key, value);
          batchStatements.push(stmt);
        }
      }

      // 执行配置批量操作
      if (batchStatements.length > 0) {
        await this.db.batch(batchStatements);
      }

      return {
        success: true,
        stats,
      };
    } catch (error) {
      console.error('导入数据失败:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : '未知错误',
      };
    }
  }

  // 根据名称查询分组
  async getGroupByName(name: string): Promise<Group | null> {
    const result = await this.db
      .prepare('SELECT id, name, order_num, created_at, updated_at FROM groups WHERE name = ?')
      .bind(name)
      .first<Group>();
    return result;
  }

  // 查询特定分组下是否已存在指定URL的站点
  async getSiteByGroupIdAndUrl(groupId: number, url: string): Promise<Site | null> {
    const result = await this.db
      .prepare(
        'SELECT id, group_id, name, url, icon, description, notes, order_num, created_at, updated_at FROM sites WHERE group_id = ? AND url = ?'
      )
      .bind(groupId, url)
      .first<Site>();
    return result;
  }
}

// 创建 API 辅助函数
export function createAPI(env: Env): NavigationAPI {
  return new NavigationAPI(env);
}
