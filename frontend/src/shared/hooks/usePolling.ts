import { useEffect, useRef, useCallback } from 'react';

interface UsePollingOptions {
  /** Polling interval in milliseconds */
  interval: number;
  /** Whether polling is enabled */
  enabled?: boolean;
  /** Callback to execute on each poll */
  onPoll: () => void | Promise<void>;
  /** Optional condition to stop polling */
  stopCondition?: () => boolean;
}

/**
 * Custom hook for polling with automatic cleanup
 * Follows react-best-practices: client-event-listeners rule
 */
export function usePolling({
  interval,
  enabled = true,
  onPoll,
  stopCondition,
}: UsePollingOptions): void {
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const onPollRef = useRef(onPoll);
  const stopConditionRef = useRef(stopCondition);

  // Keep refs updated to avoid stale closures
  useEffect(() => {
    onPollRef.current = onPoll;
    stopConditionRef.current = stopCondition;
  }, [onPoll, stopCondition]);

  const clearPolling = useCallback(() => {
    if (intervalRef.current) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
  }, []);

  useEffect(() => {
    if (!enabled) {
      clearPolling();
      return;
    }

    // Initial poll
    onPollRef.current();

    // Set up interval
    intervalRef.current = setInterval(() => {
      if (stopConditionRef.current?.()) {
        clearPolling();
        return;
      }
      onPollRef.current();
    }, interval);

    return clearPolling;
  }, [enabled, interval, clearPolling]);
}

export default usePolling;
