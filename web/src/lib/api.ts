import axios, { AxiosInstance, AxiosError } from "axios";
import { ScanRequest, ScanResponse } from "@/types/api.types";

const API_BASE_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";

class ApiClient {
    private client: AxiosInstance;

    constructor() {
        this.client = axios.create({
            baseURL: API_BASE_URL,
            headers: {
                "Content-Type": "application/json",
            },
            timeout: 30000,
        });

        // Request interceptor
        this.client.interceptors.request.use(
            (config) => {
                // Add any auth headers here if needed
                return config;
            },
            (error) => {
                return Promise.reject(error);
            }
        );

        // Response interceptor
        this.client.interceptors.response.use(
            (response) => response,
            (error: AxiosError) => {
                if (error.response) {
                    // Server responded with error
                    console.error("API Error:", error.response.status, error.response.data);
                } else if (error.request) {
                    // Request made but no response
                    console.error("Network Error:", error.message);
                } else {
                    // Something else happened
                    console.error("Error:", error.message);
                }
                return Promise.reject(error);
            }
        );
    }

    async scan(request: ScanRequest): Promise<ScanResponse> {
        const response = await this.client.post<ScanResponse>("/api/scan", request);
        return response.data;
    }

    async getHistory(): Promise<ScanResponse[]> {
        const response = await this.client.get<ScanResponse[]>("/api/history");
        return response.data;
    }

    async getHistoryItem(id: string): Promise<ScanResponse> {
        const response = await this.client.get<ScanResponse>(`/api/history/${id}`);
        return response.data;
    }

    async deleteHistoryItem(id: string): Promise<void> {
        await this.client.delete(`/api/history/${id}`);
    }

    async clearHistory(): Promise<void> {
        await this.client.delete("/api/history");
    }

    async getPatterns(): Promise<{ patterns: { id: string; name: string; description: string; regex: string }[] }> {
        const response = await this.client.get("/api/patterns");
        return response.data;
    }
}

export const api = new ApiClient();
