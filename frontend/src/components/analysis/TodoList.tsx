import { CheckCircle2, Circle, Loader2 } from 'lucide-react'

interface Todo {
  id: string
  content: string
  status: 'pending' | 'in_progress' | 'completed'
  priority?: 'high' | 'medium' | 'low'
}

interface TodoListProps {
  todos: Todo[]
}

export function TodoList({ todos }: TodoListProps) {
  if (!todos || todos.length === 0) {
    return null
  }

  const completed = todos.filter(t => t.status === 'completed').length
  const total = todos.length

  return (
    <div>
      <div className="flex items-center justify-between mb-3">
        <h4 className="text-sm font-medium">分析计划</h4>
        <span className="text-xs text-muted-foreground">
          {completed}/{total} 完成
        </span>
      </div>
      <div className="space-y-2">
        {todos.map((todo) => (
          <div
            key={todo.id}
            className={`flex items-start gap-2 p-2 rounded-lg ${
              todo.status === 'in_progress' 
                ? 'bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800' 
                : 'bg-muted/30'
            }`}
          >
            <TodoStatusIcon status={todo.status} />
            <span className={`text-sm flex-1 ${
              todo.status === 'completed' 
                ? 'text-muted-foreground line-through' 
                : todo.status === 'in_progress'
                  ? 'font-medium'
                  : ''
            }`}>
              {todo.content}
            </span>
            {todo.priority === 'high' && (
              <span className="text-xs text-red-500 font-medium">!</span>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

function TodoStatusIcon({ status }: { status: string }) {
  if (status === 'completed') {
    return <CheckCircle2 className="h-4 w-4 text-green-500 flex-shrink-0 mt-0.5" />
  }
  if (status === 'in_progress') {
    return <Loader2 className="h-4 w-4 text-blue-500 animate-spin flex-shrink-0 mt-0.5" />
  }
  return <Circle className="h-4 w-4 text-muted-foreground flex-shrink-0 mt-0.5" />
}
