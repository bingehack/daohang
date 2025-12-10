import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

// 获取当前文件路径
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// 验证JSON文件
const jsonFile = path.join(__dirname, 'navigator_output_fixed.json');

try {
  const jsonData = fs.readFileSync(jsonFile, 'utf8');
  const data = JSON.parse(jsonData);
  console.log('JSON文件格式有效！');
  console.log('文件包含以下键:', Object.keys(data));
  console.log(`包含 ${data.groups ? data.groups.length : 0} 个分组`);
  console.log(`包含 ${data.sites ? data.sites.length : 0} 个站点`);
} catch (error) {
  console.error('JSON文件格式无效:', error);
}
