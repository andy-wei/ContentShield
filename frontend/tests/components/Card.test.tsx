/** Card 组件测试。 */
import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { Card } from '../../src/components/Card'

describe('Card', () => {
  it('渲染 children', () => {
    render(<Card>内容</Card>)
    expect(screen.getByText('内容')).toBeInTheDocument()
  })

  it('渲染标题', () => {
    render(<Card title="标题">内容</Card>)
    expect(screen.getByText('标题')).toBeInTheDocument()
  })

  it('渲染副标题', () => {
    render(<Card title="主" subtitle="副">内容</Card>)
    expect(screen.getByText('主')).toBeInTheDocument()
    expect(screen.getByText('副')).toBeInTheDocument()
  })

  it('渲染 actions', () => {
    render(
      <Card title="T" actions={<button>操作</button>}>
        内容
      </Card>,
    )
    expect(screen.getByText('操作')).toBeInTheDocument()
  })

  it('无 title 和 actions 时不渲染头部', () => {
    const { container } = render(<Card>内容</Card>)
    // 头部有 border-b 类，无 title/actions 时不应出现
    const headers = container.querySelectorAll('.border-b.border-slate-100')
    expect(headers.length).toBe(0)
  })

  it('有 title 时渲染头部', () => {
    const { container } = render(<Card title="T">内容</Card>)
    const headers = container.querySelectorAll('.border-b.border-slate-100')
    expect(headers.length).toBe(1)
  })

  it('自定义 className 被合并', () => {
    const { container } = render(<Card className="my-custom">x</Card>)
    expect(container.firstChild).toHaveClass('my-custom')
  })

  it('保留基础样式', () => {
    const { container } = render(<Card>x</Card>)
    expect(container.firstChild).toHaveClass('rounded-xl')
    expect(container.firstChild).toHaveClass('bg-white')
    expect(container.firstChild).toHaveClass('shadow-sm')
  })

  it('children 始终渲染在 body 区', () => {
    render(<Card title="T"><span>子内容</span></Card>)
    expect(screen.getByText('子内容')).toBeInTheDocument()
  })
})
