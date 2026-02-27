/**
 * Format file size in human-readable format
 */
export function formatFileSize(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}

/**
 * Format a hash string with truncation
 */
export function formatHash(hash: string | undefined, length = 12): string {
  if (!hash) return 'N/A';
  if (hash.length <= length) return hash;
  return `${hash.slice(0, length)}...`;
}

/**
 * Format confidence as percentage
 */
export function formatConfidence(confidence: number): string {
  return `${(confidence * 100).toFixed(0)}%`;
}

/**
 * Format a preview value for display
 */
export function formatPreviewValue(value: unknown): string {
  if (typeof value === 'number') return value.toString();
  if (typeof value === 'string') return value;
  if (typeof value === 'boolean') return value ? 'Yes' : 'No';
  if (Array.isArray(value)) {
    return value.slice(0, 3).join(', ') + (value.length > 3 ? '...' : '');
  }
  return JSON.stringify(value);
}

/**
 * Normalize a list, filtering out falsy values
 */
export function normalizeList<T>(items: T[] | undefined | null): T[] {
  return Array.isArray(items) ? items.filter(Boolean) : [];
}

/**
 * Capitalize first letter
 */
export function capitalize(str: string): string {
  if (!str) return '';
  return str.charAt(0).toUpperCase() + str.slice(1);
}
