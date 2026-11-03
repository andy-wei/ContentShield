/** DecisionBadge 组件测试。 */
import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { DecisionBadge } from '../../src/components/Badge'

describe('DecisionBadge', () => {
  it('block 渲染拦截文案', () => {
    render(<DecisionBadge decision="block" />)
    expect(screen.getByText('拦截')).toBeInTheDocument()
  })

  it('warn 渲染警告文案', () => {
    render(<DecisionBadge decision="warn" />)
    expect(screen.getByText('警告')).toBeInTheDocument()
  })

  it('pass 渲染通过文案', () => {
    render(<DecisionBadge decision="pass" />)
    expect(screen.getByText('通过')).toBeInTheDocument()
  })

  it('skipped 渲染跳过文案', () => {
    render(<DecisionBadge decision="skipped" />)
    expect(screen.getByText('跳过')).toBeInTheDocument()
  })

  it('渲染圆点指示器', () => {
    const { container } = render(<DecisionBadge decision="block" />)
    const dot = container.querySelector('.rounded-full.h-1\\.5')
    expect(dot).not.toBeNull()
  })

  it('block 应用红色徽章样式', () => {
    const { container } = render(<DecisionBadge decision="block" />)
    expect(container.firstChild).toHaveClass('text-rose-700')
  })

  it('自定义 className 被合并', () => {
    const { container } = render(<DecisionBadge decision="pass" className="extra" />)
    expect(container.firstChild).toHaveClass('extra')
  })

  it('保留基础徽章样式（圆角、边框、内边距）', () => {
    const { container } = render(<DecisionBadge decision="pass" />)
    const el = container.firstChild as HTMLElement
    expect(el).toHaveClass('inline-flex')
    expect(el).toHaveClass('rounded-full')
    expect(el).toHaveClass('border')
  })
})
