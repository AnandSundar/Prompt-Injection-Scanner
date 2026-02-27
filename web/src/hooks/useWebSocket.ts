import { useEffect, useRef, useCallback, useState } from "react";
import { ScanResponse } from "@/types/api.types";

interface UseWebSocketOptions {
    url?: string;
    onMessage?: (data: ScanResponse) => void;
    onError?: (error: Event) => void;
    onOpen?: () => void;
    onClose?: () => void;
}

interface UseWebSocketReturn {
    isConnected: boolean;
    sendMessage: (data: unknown) => void;
    connect: () => void;
    disconnect: () => void;
}

export function useWebSocket(options: UseWebSocketOptions = {}): UseWebSocketReturn {
    const {
        url = import.meta.env.VITE_WS_URL || "ws://localhost:8000/ws",
        onMessage,
        onError,
        onOpen,
        onClose,
    } = options;

    const wsRef = useRef<WebSocket | null>(null);
    const [isConnected, setIsConnected] = useState(false);
    const reconnectTimeoutRef = useRef<number | null>(null);
    const reconnectAttempts = useRef(0);
    const maxReconnectAttempts = 5;

    const connect = useCallback(() => {
        if (wsRef.current?.readyState === WebSocket.OPEN) {
            return;
        }

        try {
            const ws = new WebSocket(url);
            wsRef.current = ws;

            ws.onopen = () => {
                setIsConnected(true);
                reconnectAttempts.current = 0;
                onOpen?.();
            };

            ws.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data) as ScanResponse;
                    onMessage?.(data);
                } catch (error) {
                    console.error("Failed to parse WebSocket message:", error);
                }
            };

            ws.onerror = (error) => {
                console.error("WebSocket error:", error);
                onError?.(error);
            };

            ws.onclose = () => {
                setIsConnected(false);
                onClose?.();

                // Attempt reconnection
                if (reconnectAttempts.current < maxReconnectAttempts) {
                    const delay = Math.min(1000 * Math.pow(2, reconnectAttempts.current), 30000);
                    reconnectTimeoutRef.current = window.setTimeout(() => {
                        reconnectAttempts.current++;
                        connect();
                    }, delay);
                }
            };
        } catch (error) {
            console.error("Failed to create WebSocket:", error);
        }
    }, [url, onMessage, onError, onOpen, onClose]);

    const disconnect = useCallback(() => {
        if (reconnectTimeoutRef.current) {
            clearTimeout(reconnectTimeoutRef.current);
            reconnectTimeoutRef.current = null;
        }

        if (wsRef.current) {
            wsRef.current.close();
            wsRef.current = null;
        }
        setIsConnected(false);
    }, []);

    const sendMessage = useCallback((data: unknown) => {
        if (wsRef.current?.readyState === WebSocket.OPEN) {
            wsRef.current.send(JSON.stringify(data));
        } else {
            console.warn("WebSocket is not connected");
        }
    }, []);

    useEffect(() => {
        return () => {
            disconnect();
        };
    }, [disconnect]);

    return {
        isConnected,
        sendMessage,
        connect,
        disconnect,
    };
}
