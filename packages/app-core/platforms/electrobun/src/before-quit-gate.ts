export interface BeforeQuitEvent {
  response?: { allow: boolean };
}

export interface BeforeQuitGate {
  allowNextQuit(): void;
  handle(event: BeforeQuitEvent): void;
}

/**
 * Convert Electrobun's synchronous before-quit decision into an asynchronous
 * cleanup gate. The first event is denied immediately; cleanup then reissues
 * Utils.quit with a one-use pass that prevents a recursive cleanup loop.
 */
export function createBeforeQuitGate(options: {
  cleanup: () => Promise<void>;
  onCleanupError: (error: unknown) => void;
  quit: () => void;
}): BeforeQuitGate {
  let allowNextQuit = false;
  let pendingCleanup: Promise<void> | null = null;

  return {
    allowNextQuit: () => {
      allowNextQuit = true;
    },
    handle: (event) => {
      if (allowNextQuit) {
        allowNextQuit = false;
        event.response = { allow: true };
        return;
      }

      // Electrobun does not await listener promises, so cancellation must be
      // written before this handler returns.
      event.response = { allow: false };
      if (pendingCleanup) return;

      const cleanupAttempt = (async () => {
        try {
          await options.cleanup();
          allowNextQuit = true;
          options.quit();
        } catch (error) {
          allowNextQuit = false;
          options.onCleanupError(error);
        }
      })();
      pendingCleanup = cleanupAttempt;
      void cleanupAttempt.finally(() => {
        if (pendingCleanup === cleanupAttempt) pendingCleanup = null;
      });
    },
  };
}
