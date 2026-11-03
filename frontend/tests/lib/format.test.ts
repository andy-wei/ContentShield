/** format.ts 纯函数测试。 */
import { describe, it, expect } from 'vitest'
import {
  cn,
  decisionStyle,
  layerLabel,
  riskColor,
  formatDateTime,
  formatNumber,
} from '../../src/lib/format'

describe('cn', () => {
  it('合并多个 class', () => {
    expect(cn('a', 'b', 'c')).toBe('a b c')
  })

  it('处理空值', () => {
    expect(cn('a', null, undefined, false, 'b')).toBe('a b')
  })

  it('无参数返回空字符串', () => {
    expect(cn()).toBe('')
  })
})

describe('decisionStyle', () => {
  it('block 有拦截文案和红色调', () => {
    expect(decisionStyle.block.label).toBe('拦截')
    expect(decisionStyle.block.badge).toContain('rose')
    expect(decisionStyle.block.dot).toContain('rose')
  })

  it('warn 有警告文案和琥珀色调', () => {
    expect(decisionStyle.warn.label).toBe('警告')
    expect(decisionStyle.warn.badge).toContain('amber')
  })

  it('pass 有通过文案和绿色调', () => {
    expect(decisionStyle.pass.label).toBe('通过')
    expect(decisionStyle.pass.badge).toContain('emerald')
  })

  it('skipped 有跳过文案和灰色调', () => {
    expect(decisionStyle.skipped.label).toBe('跳过')
    expect(decisionStyle.skipped.badge).toContain('slate')
  })

  it('每个决策都含 label/badge/text/dot 四个字段', () => {
    const keys = ['block', 'warn', 'pass', 'skipped'] as const
    for (const k of keys) {
      const s = decisionStyle[k]
      expect(s).toHaveProperty('label')
      expect(s).toHaveProperty('badge')
      expect(s).toHaveProperty('text')
      expect(s).toHaveProperty('dot')
    }
  })
})

describe('layerLabel', () => {
  it('返回 6 层中文名', () => {
    expect(layerLabel.lexicon).toBe('L0 词库')
    expect(layerLabel.prompt_guard).toBe('L1 注入检测')
    expect(layerLabel.llama_guard).toBe('L2 危害分类')
    expect(layerLabel.dlp).toBe('L3 DLP 防泄露')
    expect(layerLabel.indirect_injection).toBe('L1.5 间接注入')
    expect(layerLabel.cross_verify).toBe('L4 交叉验证')
  })

  it('未知层返回 undefined', () => {
    expect(layerLabel.unknown_layer).toBeUndefined()
  })
})

describe('riskColor', () => {
  it('高分（≥0.66）返回红色', () => {
    expect(riskColor(0.66)).toBe('text-rose-600')
    expect(riskColor(0.9)).toBe('text-rose-600')
    expect(riskColor(1.0)).toBe('text-rose-600')
  })

  it('中分（0.33-0.65）返回琥珀色', () => {
    expect(riskColor(0.33)).toBe('text-amber-600')
    expect(riskColor(0.5)).toBe('text-amber-600')
    expect(riskColor(0.65)).toBe('text-amber-600')
  })

  it('低分（<0.33）返回绿色', () => {
    expect(riskColor(0)).toBe('text-emerald-600')
    expect(riskColor(0.32)).toBe('text-emerald-600')
  })

  it('边界值 0.66 与 0.33', () => {
    expect(riskColor(0.659)).toBe('text-amber-600')
    expect(riskColor(0.329)).toBe('text-emerald-600')
  })
})

describe('formatDateTime', () => {
  it('格式化 ISO 字符串为 YYYY-MM-DD HH:mm:ss', () => {
    const result = formatDateTime('2026-07-07T15:30:45')
    // 格式校验（具体值受时区影响，只校验结构）
    expect(result).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/)
  })

  it('ISO with Z 也合法', () => {
    const result = formatDateTime('2026-01-15T08:00:00Z')
    expect(result).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/)
  })

  it('月份与日期补零', () => {
    const result = formatDateTime('2026-01-02T03:04:05')
    // 结果应含 "01" "02" "03" "04" "05" 中的部分（取决于时区，但小时以下应补零）
    expect(result).toContain('-01-')
    expect(result).toContain('-02 ')
  })
})

describe('formatNumber', () => {
  it('千分位格式化', () => {
    expect(formatNumber(1000)).toBe('1,000')
    expect(formatNumber(1234567)).toBe('1,234,567')
  })

  it('小数字不变', () => {
    expect(formatNumber(42)).toBe('42')
    expect(formatNumber(0)).toBe('0')
  })

  it('大数字', () => {
    expect(formatNumber(1000000)).toBe('1,000,000')
  })
})
