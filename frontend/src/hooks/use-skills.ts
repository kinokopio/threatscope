import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  getSkills,
  getSkill,
  updateSkillFile,
  createSkillFile,
  deleteSkillFile,
  deleteSkill,
} from '@/lib/api'

export function useSkills() {
  return useQuery({
    queryKey: ['skills'],
    queryFn: getSkills,
  })
}

export function useSkill(name: string) {
  return useQuery({
    queryKey: ['skill', name],
    queryFn: () => getSkill(name),
    enabled: !!name,
  })
}

export function useUpdateSkillFile() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ skillName, filePath, content }: { skillName: string; filePath: string; content: string }) =>
      updateSkillFile(skillName, filePath, content),
    onSuccess: (_, { skillName }) => {
      queryClient.invalidateQueries({ queryKey: ['skills'] })
      queryClient.invalidateQueries({ queryKey: ['skill', skillName] })
    },
  })
}

export function useCreateSkillFile() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ skillName, filePath, content }: { skillName: string; filePath: string; content: string }) =>
      createSkillFile(skillName, filePath, content),
    onSuccess: (_, { skillName }) => {
      queryClient.invalidateQueries({ queryKey: ['skills'] })
      queryClient.invalidateQueries({ queryKey: ['skill', skillName] })
    },
  })
}

export function useDeleteSkillFile() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ skillName, filePath }: { skillName: string; filePath: string }) =>
      deleteSkillFile(skillName, filePath),
    onSuccess: (_, { skillName }) => {
      queryClient.invalidateQueries({ queryKey: ['skills'] })
      queryClient.invalidateQueries({ queryKey: ['skill', skillName] })
    },
  })
}

export function useDeleteSkill() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: deleteSkill,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['skills'] })
    },
  })
}
