import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

// 获取当前文件路径
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// 读取JSON文件
const inputFile = path.join(__dirname, 'navigator_output.json');
const outputFile = path.join(__dirname, 'navigator_output_fixed.json');

// 修复日期格式函数
function fixDateFormat(data) {
  // 遍历所有组
  if (data.groups) {
    data.groups.forEach(group => {
      if (group.created_at) group.created_at = convertDate(group.created_at);
      if (group.updated_at) group.updated_at = convertDate(group.updated_at);
    });
  }

  // 遍历所有站点
  if (data.sites) {
    data.sites.forEach(site => {
      if (site.created_at) site.created_at = convertDate(site.created_at);
      if (site.updated_at) site.updated_at = convertDate(site.updated_at);
    });
  }

  return data;
}

// 转换日期格式函数
function convertDate(dateString) {
  // 检查是否已经是正确的格式
  if (dateString.includes('T') && dateString.endsWith('Z')) {
    return dateString;
  }

  // 将空格替换为T并添加Z时区标识
  return dateString.replace(' ', 'T') + 'Z';
}

// 主函数
function main() {
  try {
    // 读取文件
    const jsonData = fs.readFileSync(inputFile, 'utf8');
    const data = JSON.parse(jsonData);

    // 修复日期格式
    const fixedData = fixDateFormat(data);

    // 保存修复后的文件
    fs.writeFileSync(outputFile, JSON.stringify(fixedData, null, 2), 'utf8');

    console.log('日期格式修复完成！');
    console.log(`输入文件: ${inputFile}`);
    console.log(`输出文件: ${outputFile}`);
  } catch (error) {
    console.error('修复过程中发生错误:', error);
  }
}

// 执行主函数
main();
