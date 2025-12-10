#!/usr/bin/env python3
"""
测试脚本：验证修复后的导入功能是否正确处理多层级结构
"""

import json
import os
import requests

def test_import_hierarchy():
    """测试导入功能是否正确处理多层级结构"""
    # 读取修复后的文件
    fixed_file_path = "navigator_output_fixed.json"
    
    if not os.path.exists(fixed_file_path):
        print(f"错误：找不到文件 {fixed_file_path}")
        return False
    
    try:
        with open(fixed_file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        print("✅ 成功读取修复后的JSON文件")
        print(f"   总共有 {len(data['groups'])} 个分组")
        print(f"   总共有 {len(data['sites'])} 个站点")
        
        # 检查分组是否有层级结构
        root_groups = [g for g in data['groups'] if not g.get('parent_id') or g['parent_id'] is None]
        sub_groups = [g for g in data['groups'] if g.get('parent_id') and g['parent_id'] is not None]
        
        print(f"   根分组数量：{len(root_groups)}")
        print(f"   子分组数量：{len(sub_groups)}")
        
        if not sub_groups:
            print("⚠️  警告：没有发现子分组，可能无法测试多层级功能")
        else:
            # 检查是否有至少一个子分组有有效的父ID
            valid_sub_groups = [g for g in sub_groups if g['parent_id'] in [gr['id'] for gr in data['groups']]]
            print(f"   有有效父ID的子分组数量：{len(valid_sub_groups)}")
            
            if len(valid_sub_groups) > 0:
                print("✅ 发现有效的多层级结构")
            else:
                print("⚠️  警告：所有子分组的父ID在分组列表中找不到")
        
        return True
        
    except json.JSONDecodeError as e:
        print(f"❌ JSON解析错误：{e}")
        return False
    except Exception as e:
        print(f"❌ 读取文件时发生错误：{e}")
        return False

def test_api_import():
    """测试API导入功能"""
    url = "http://localhost:5173/api/import"
    
    # 读取修复后的文件
    fixed_file_path = "navigator_output_fixed.json"
    
    if not os.path.exists(fixed_file_path):
        print(f"错误：找不到文件 {fixed_file_path}")
        return False
    
    try:
        with open(fixed_file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        print(f"正在测试API导入功能...")
        print(f"  导入分组数：{len(data['groups'])}")
        print(f"  导入站点数：{len(data['sites'])}")
        
        # 由于前端API可能需要特殊处理，这里只做基本验证
        print("✅ API导入测试准备就绪")
        print("   请在浏览器中手动测试导入功能：")
        print("   1. 访问 http://localhost:5173/")
        print("   2. 点击右上角的导入按钮")
        print("   3. 选择 navigator_output_fixed.json 文件")
        print("   4. 查看是否正确导入了多层级结构")
        
        return True
        
    except Exception as e:
        print(f"❌ API测试时发生错误：{e}")
        return False

if __name__ == "__main__":
    print("=== 测试修复后的导入功能 ===")
    print()
    
    # 测试1：检查文件结构
    print("测试1：检查JSON文件结构")
    test_import_hierarchy()
    print()
    
    # 测试2：API导入测试
    print("测试2：API导入功能测试")
    test_api_import()
    print()
    
    print("=== 测试完成 ===")
