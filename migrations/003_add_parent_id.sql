-- 向groups表添加parent_id字段，支持多层级分类结构
ALTER TABLE groups ADD COLUMN IF NOT EXISTS parent_id INTEGER DEFAULT NULL;

-- 添加外键约束，确保parent_id指向有效的分组ID
ALTER TABLE groups ADD CONSTRAINT IF NOT EXISTS fk_groups_parent_id FOREIGN KEY (parent_id) REFERENCES groups(id) ON DELETE CASCADE;
