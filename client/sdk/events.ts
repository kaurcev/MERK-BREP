export type EventMap = Record<string, any[]>;

export interface IEventEmitter<T extends EventMap> {
  on<K extends keyof T>(event: K, listener: (...args: T[K]) => void): void;
  off<K extends keyof T>(event: K, listener: (...args: T[K]) => void): void;
  once<K extends keyof T>(event: K, listener: (...args: T[K]) => void): void;
  emit<K extends keyof T>(event: K, ...args: T[K]): void;
}

export class TypedEventEmitter<T extends EventMap> implements IEventEmitter<T> {
  private listeners: Map<keyof T, Set<(...args: unknown[]) => void>> = new Map();

  on<K extends keyof T>(event: K, listener: (...args: T[K]) => void): void {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }
    this.listeners.get(event)!.add(listener as (...args: unknown[]) => void);
  }

  off<K extends keyof T>(event: K, listener: (...args: T[K]) => void): void {
    const set = this.listeners.get(event);
    if (set) {
      set.delete(listener as (...args: unknown[]) => void);
    }
  }

  once<K extends keyof T>(event: K, listener: (...args: T[K]) => void): void {
    const wrapper = (...args: T[K]) => {
      this.off(event, wrapper);
      listener(...args);
    };
    this.on(event, wrapper);
  }

  emit<K extends keyof T>(event: K, ...args: T[K]): void {
    const set = this.listeners.get(event);
    if (set) {
      set.forEach(listener => listener(...args));
    }
  }
}