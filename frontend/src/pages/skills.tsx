import { useState, useEffect } from 'react'
import {
  Sparkles,
  Trash2,
  X,
  Save,
  Loader2,
  FolderOpen,
  FileText,
  ChevronRight,
  ChevronDown,
  Clock,
  HardDrive,
  FilePlus,
} from 'lucide-react'
import { toast } from 'sonner'
import { Card, CardContent } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { ScrollArea } from '@/components/ui/scroll-area'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import {
  useSkills,
  useSkill,
  useUpdateSkillFile,
  useCreateSkillFile,
  useDeleteSkillFile,
  useDeleteSkill,
} from '@/hooks/use-skills'
import type { SkillInfo, SkillFileInfo } from '@/lib/api'

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i]
}

function formatDate(dateStr: string): string {
  return new Date(dateStr).toLocaleString('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  })
}

function SkillCard({
  skill,
  isSelected,
  onSelect,
  onDelete,
}: {
  skill: SkillInfo
  isSelected: boolean
  onSelect: () => void
  onDelete: () => void
}) {
  return (
    <Card
      className={`cursor-pointer transition-all hover:bg-muted/50 ${isSelected ? 'ring-2 ring-primary' : ''}`}
      onClick={onSelect}
    >
      <CardContent className="p-4">
        <div className="flex items-start gap-3">
          <div className="flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-lg bg-primary/10">
            <FolderOpen className="h-5 w-5 text-primary" />
          </div>
          <div className="min-w-0 flex-1">
            <div className="mb-1 flex items-center gap-2">
              <h3 className="font-medium">{skill.folder_name}</h3>
              <Badge variant="outline" className="text-xs">
                {skill.files.length} 文件
              </Badge>
            </div>
            <p className="line-clamp-2 text-sm text-muted-foreground">
              {skill.description || '无描述'}
            </p>
            <div className="mt-2 flex items-center gap-4 text-xs text-muted-foreground">
              <span className="flex items-center gap-1">
                <HardDrive className="h-3 w-3" />
                {formatBytes(skill.total_size)}
              </span>
              <span className="flex items-center gap-1">
                <Clock className="h-3 w-3" />
                {formatDate(skill.modified_at)}
              </span>
            </div>
          </div>
          <Button
            variant="ghost"
            size="icon"
            onClick={(e) => {
              e.stopPropagation()
              onDelete()
            }}
            className="text-destructive hover:text-destructive"
          >
            <Trash2 className="h-4 w-4" />
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}

function FileTree({
  files,
  selectedFile,
  onSelectFile,
  onDeleteFile,
  skillName,
}: {
  files: SkillFileInfo[]
  selectedFile: string | null
  onSelectFile: (path: string) => void
  onDeleteFile: (path: string) => void
  skillName: string
}) {
  const [expanded, setExpanded] = useState(true)

  return (
    <div className="space-y-1">
      <div
        className="flex cursor-pointer items-center gap-1 rounded px-2 py-1 hover:bg-muted"
        onClick={() => setExpanded(!expanded)}
      >
        {expanded ? (
          <ChevronDown className="h-4 w-4" />
        ) : (
          <ChevronRight className="h-4 w-4" />
        )}
        <FolderOpen className="h-4 w-4 text-primary" />
        <span className="font-medium">{skillName}</span>
      </div>
      {expanded && (
        <div className="ml-4 space-y-0.5">
          {files.map((file) => (
            <div
              key={file.path}
              className={`group flex cursor-pointer items-center gap-2 rounded px-2 py-1 hover:bg-muted ${
                selectedFile === file.name ? 'bg-muted' : ''
              }`}
              onClick={() => onSelectFile(file.name)}
            >
              <FileText className="h-4 w-4 text-muted-foreground" />
              <span className="flex-1 truncate text-sm">{file.name}</span>
              <span className="text-xs text-muted-foreground">
                {formatBytes(file.size)}
              </span>
              {file.name !== 'SKILL.md' && (
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-6 w-6 opacity-0 group-hover:opacity-100"
                  onClick={(e) => {
                    e.stopPropagation()
                    onDeleteFile(file.name)
                  }}
                >
                  <Trash2 className="h-3 w-3 text-destructive" />
                </Button>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function FileEditor({
  skillName,
  file,
  onClose,
}: {
  skillName: string
  file: SkillFileInfo
  onClose: () => void
}) {
  const [content, setContent] = useState(file.content || '')
  const [hasChanges, setHasChanges] = useState(false)
  const updateFile = useUpdateSkillFile()

  useEffect(() => {
    setContent(file.content || '')
    setHasChanges(false)
  }, [file])

  const handleSave = async () => {
    try {
      await updateFile.mutateAsync({
        skillName,
        filePath: file.name,
        content,
      })
      toast.success('文件已保存')
      setHasChanges(false)
    } catch {
      toast.error('保存失败')
    }
  }

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center justify-between border-b px-4 py-2">
        <div className="flex items-center gap-2">
          <FileText className="h-4 w-4" />
          <span className="font-medium">{file.name}</span>
          {hasChanges && (
            <Badge variant="secondary" className="text-xs">
              未保存
            </Badge>
          )}
        </div>
        <div className="flex items-center gap-2">
          <Button
            size="sm"
            variant="outline"
            onClick={onClose}
          >
            <X className="mr-1 h-4 w-4" />
            关闭
          </Button>
          <Button
            size="sm"
            onClick={handleSave}
            disabled={!hasChanges || updateFile.isPending}
          >
            {updateFile.isPending ? (
              <Loader2 className="mr-1 h-4 w-4 animate-spin" />
            ) : (
              <Save className="mr-1 h-4 w-4" />
            )}
            保存
          </Button>
        </div>
      </div>
      <div className="flex-1 p-2">
        <Textarea
          value={content}
          onChange={(e: React.ChangeEvent<HTMLTextAreaElement>) => {
            setContent(e.target.value)
            setHasChanges(e.target.value !== file.content)
          }}
          className="h-full min-h-[400px] resize-none font-mono text-sm"
          placeholder="文件内容..."
        />
      </div>
    </div>
  )
}

function SkillDetailPanel({
  skillName,
  onClose,
}: {
  skillName: string
  onClose: () => void
}) {
  const { data: skill, isLoading } = useSkill(skillName)
  const [selectedFile, setSelectedFile] = useState<string | null>(null)
  const [newFileOpen, setNewFileOpen] = useState(false)
  const [newFileName, setNewFileName] = useState('')
  const [deleteFileConfirm, setDeleteFileConfirm] = useState<string | null>(null)
  const createFile = useCreateSkillFile()
  const deleteFile = useDeleteSkillFile()

  const selectedFileData = skill?.files.find((f) => f.name === selectedFile)

  const handleCreateFile = async () => {
    if (!newFileName) {
      toast.error('请输入文件名')
      return
    }
    try {
      await createFile.mutateAsync({
        skillName,
        filePath: newFileName,
        content: '',
      })
      toast.success('文件已创建')
      setNewFileOpen(false)
      setNewFileName('')
      setSelectedFile(newFileName)
    } catch {
      toast.error('创建失败')
    }
  }

  const handleDeleteFile = async () => {
    if (!deleteFileConfirm) return
    try {
      await deleteFile.mutateAsync({
        skillName,
        filePath: deleteFileConfirm,
      })
      toast.success('文件已删除')
      if (selectedFile === deleteFileConfirm) {
        setSelectedFile(null)
      }
      setDeleteFileConfirm(null)
    } catch {
      toast.error('删除失败')
    }
  }

  if (isLoading) {
    return (
      <div className="flex h-full items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    )
  }

  if (!skill) {
    return (
      <div className="flex h-full items-center justify-center">
        <p className="text-muted-foreground">技能不存在</p>
      </div>
    )
  }

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center justify-between border-b px-4 py-3">
        <div>
          <h3 className="font-semibold">{skill.folder_name}</h3>
          <p className="text-sm text-muted-foreground line-clamp-1">
            {skill.description}
          </p>
        </div>
        <Button variant="ghost" size="icon" onClick={onClose}>
          <X className="h-4 w-4" />
        </Button>
      </div>

      <div className="flex flex-1 overflow-hidden">
        <div className="w-64 border-r p-3">
          <div className="mb-3 flex items-center justify-between">
            <span className="text-sm font-medium">文件</span>
            <Button
              variant="ghost"
              size="icon"
              className="h-7 w-7"
              onClick={() => setNewFileOpen(true)}
            >
              <FilePlus className="h-4 w-4" />
            </Button>
          </div>
          <ScrollArea className="h-[calc(100%-40px)]">
            <FileTree
              files={skill.files}
              selectedFile={selectedFile}
              onSelectFile={setSelectedFile}
              onDeleteFile={setDeleteFileConfirm}
              skillName={skill.folder_name}
            />
          </ScrollArea>
        </div>

        <div className="flex-1">
          {selectedFileData ? (
            <FileEditor
              skillName={skillName}
              file={selectedFileData}
              onClose={() => setSelectedFile(null)}
            />
          ) : (
            <div className="flex h-full items-center justify-center">
              <div className="text-center">
                <FileText className="mx-auto mb-2 h-12 w-12 text-muted-foreground" />
                <p className="text-muted-foreground">选择文件进行编辑</p>
              </div>
            </div>
          )}
        </div>
      </div>

      <Dialog open={newFileOpen} onOpenChange={setNewFileOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>新建文件</DialogTitle>
            <DialogDescription>在技能文件夹中创建新文件</DialogDescription>
          </DialogHeader>
          <div>
            <Label htmlFor="new-file-name">文件名</Label>
            <Input
              id="new-file-name"
              placeholder="example.md"
              value={newFileName}
              onChange={(e) => setNewFileName(e.target.value)}
            />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setNewFileOpen(false)}>
              取消
            </Button>
            <Button onClick={handleCreateFile} disabled={createFile.isPending}>
              {createFile.isPending && (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              )}
              创建
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <AlertDialog
        open={!!deleteFileConfirm}
        onOpenChange={(open: boolean) => !open && setDeleteFileConfirm(null)}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>确认删除文件</AlertDialogTitle>
            <AlertDialogDescription>
              确定要删除文件 "{deleteFileConfirm}" 吗？
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>取消</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleDeleteFile}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              删除
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}

export function SkillsPage() {
  const { data: skills, isLoading } = useSkills()
  const deleteSkill = useDeleteSkill()

  const [selectedSkill, setSelectedSkill] = useState<string | null>(null)
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null)

  const handleDelete = async () => {
    if (!deleteConfirm) return

    try {
      await deleteSkill.mutateAsync(deleteConfirm)
      toast.success('技能已删除')
      if (selectedSkill === deleteConfirm) {
        setSelectedSkill(null)
      }
      setDeleteConfirm(null)
    } catch {
      toast.error('删除失败')
    }
  }

  return (
    <div className="flex h-[calc(100vh-4rem)] flex-col">
      <div className="border-b px-6 py-4">
        <div className="flex items-center gap-4">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
            <Sparkles className="h-5 w-5 text-primary" />
          </div>
          <div className="flex-1">
            <h2 className="text-lg font-semibold">技能管理</h2>
            <p className="text-sm text-muted-foreground">
              管理 Claude Skills 文件夹，增强 AI 恶意软件分析能力
            </p>
          </div>
        </div>
      </div>

      <div className="flex flex-1 overflow-hidden">
        <div className="w-[400px] overflow-auto border-r p-4">
          {isLoading ? (
            <div className="flex h-full items-center justify-center">
              <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
            </div>
          ) : skills && skills.length > 0 ? (
            <div className="space-y-3">
              {skills.map((skill) => (
                <SkillCard
                  key={skill.folder_name}
                  skill={skill}
                  isSelected={selectedSkill === skill.folder_name}
                  onSelect={() => setSelectedSkill(skill.folder_name)}
                  onDelete={() => setDeleteConfirm(skill.folder_name)}
                />
              ))}
            </div>
          ) : (
            <div className="flex h-full items-center justify-center">
              <div className="text-center">
                <Sparkles className="mx-auto mb-4 h-12 w-12 text-muted-foreground" />
                <h3 className="mb-2 text-lg font-medium">暂无技能</h3>
                <p className="text-sm text-muted-foreground">
                  在 .claude/skills 目录下添加技能文件夹
                </p>
              </div>
            </div>
          )}
        </div>

        <div className="flex-1">
          {selectedSkill ? (
            <SkillDetailPanel
              skillName={selectedSkill}
              onClose={() => setSelectedSkill(null)}
            />
          ) : (
            <div className="flex h-full items-center justify-center">
              <div className="text-center">
                <FolderOpen className="mx-auto mb-4 h-12 w-12 text-muted-foreground" />
                <h3 className="mb-2 text-lg font-medium">选择技能</h3>
                <p className="text-muted-foreground">
                  从左侧选择一个技能查看和编辑文件
                </p>
              </div>
            </div>
          )}
        </div>
      </div>

      <AlertDialog
        open={!!deleteConfirm}
        onOpenChange={(open: boolean) => !open && setDeleteConfirm(null)}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>确认删除技能</AlertDialogTitle>
            <AlertDialogDescription>
              确定要删除技能文件夹 "{deleteConfirm}" 及其所有文件吗？此操作无法撤销。
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>取消</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleDelete}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {deleteSkill.isPending && (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              )}
              删除
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
