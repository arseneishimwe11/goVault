// Example API worker for your backend endpoints
// This runs on Cloudflare Workers at the edge

// You can import types and utilities (they'll be bundled by esbuild)
interface User {
  id: string;
  name: string;
  email: string;
  createdAt: string;
}

interface TodoItem {
  id: string;
  userId: string;
  title: string;
  completed: boolean;
  createdAt: string;
}

// Mock data - in production, you'd use a database like D1 or KV
const mockUsers: User[] = [
  { id: "1", name: "Alice Johnson", email: "alice@example.com", createdAt: "2024-01-01" },
  { id: "2", name: "Bob Smith", email: "bob@example.com", createdAt: "2024-01-02" },
];

const mockTodos: TodoItem[] = [
  { id: "1", userId: "1", title: "Deploy to Cloudflare", completed: true, createdAt: "2024-01-01" },
  { id: "2", userId: "1", title: "Add authentication", completed: false, createdAt: "2024-01-02" },
];

// Helper function for CORS headers
function corsHeaders(origin: string): HeadersInit {
  return {
    "Access-Control-Allow-Origin": origin || "*",
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Content-Type": "application/json",
  };
}

// Main worker handler
export default {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const method = request.method;
    const origin = request.headers.get("Origin") || "*";
    
    // Handle CORS preflight
    if (method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders(origin) });
    }
    
    // Router - match paths and methods
    try {
      // GET /api/health - Health check endpoint
      if (url.pathname === "/api/health" && method === "GET") {
        return Response.json(
          { 
            status: "healthy", 
            timestamp: new Date().toISOString(),
            version: "1.0.0"
          },
          { headers: corsHeaders(origin) }
        );
      }
      
      // GET /api/users - List all users
      if (url.pathname === "/api/users" && method === "GET") {
        return Response.json(
          { users: mockUsers },
          { headers: corsHeaders(origin) }
        );
      }
      
      // GET /api/users/:id - Get specific user
      const userMatch = url.pathname.match(/^\/api\/users\/(\d+)$/);
      if (userMatch && method === "GET") {
        const userId = userMatch[1];
        const user = mockUsers.find(u => u.id === userId);
        
        if (!user) {
          return Response.json(
            { error: "User not found" },
            { status: 404, headers: corsHeaders(origin) }
          );
        }
        
        return Response.json(
          { user },
          { headers: corsHeaders(origin) }
        );
      }
      
      // POST /api/users - Create new user
      if (url.pathname === "/api/users" && method === "POST") {
        const body = await request.json() as Partial<User>;
        
        // Validate input
        if (!body.name || !body.email) {
          return Response.json(
            { error: "Name and email are required" },
            { status: 400, headers: corsHeaders(origin) }
          );
        }
        
        const newUser: User = {
          id: String(mockUsers.length + 1),
          name: body.name,
          email: body.email,
          createdAt: new Date().toISOString(),
        };
        
        // In production, you'd save to database here
        mockUsers.push(newUser);
        
        return Response.json(
          { user: newUser },
          { status: 201, headers: corsHeaders(origin) }
        );
      }
      
      // GET /api/todos - List todos with optional filtering
      if (url.pathname === "/api/todos" && method === "GET") {
        const userId = url.searchParams.get("userId");
        const completed = url.searchParams.get("completed");
        
        let filteredTodos = mockTodos;
        
        if (userId) {
          filteredTodos = filteredTodos.filter(t => t.userId === userId);
        }
        
        if (completed !== null) {
          filteredTodos = filteredTodos.filter(t => t.completed === (completed === "true"));
        }
        
        return Response.json(
          { todos: filteredTodos },
          { headers: corsHeaders(origin) }
        );
      }
      
      // PUT /api/todos/:id - Update todo
      const todoMatch = url.pathname.match(/^\/api\/todos\/(\d+)$/);
      if (todoMatch && method === "PUT") {
        const todoId = todoMatch[1];
        const body = await request.json() as Partial<TodoItem>;
        
        const todoIndex = mockTodos.findIndex(t => t.id === todoId);
        if (todoIndex === -1) {
          return Response.json(
            { error: "Todo not found" },
            { status: 404, headers: corsHeaders(origin) }
          );
        }
        
        // Update todo
        mockTodos[todoIndex] = { ...mockTodos[todoIndex], ...body };
        
        return Response.json(
          { todo: mockTodos[todoIndex] },
          { headers: corsHeaders(origin) }
        );
      }
      
      // POST /api/echo - Echo endpoint for testing
      if (url.pathname === "/api/echo" && method === "POST") {
        const body = await request.json();
        return Response.json(
          { 
            echo: body,
            headers: Object.fromEntries(request.headers.entries()),
            timestamp: new Date().toISOString()
          },
          { headers: corsHeaders(origin) }
        );
      }
      
      // 404 for unmatched routes
      return Response.json(
        { error: "Not Found", path: url.pathname },
        { status: 404, headers: corsHeaders(origin) }
      );
      
    } catch (error) {
      console.error("API Error:", error);
      return Response.json(
        { error: "Internal Server Error" },
        { status: 500, headers: corsHeaders(origin) }
      );
    }
  }
};

// You can also define environment bindings interface for type safety
// interface Env {
//   DB: D1Database;           // For SQL database
//   KV: KVNamespace;          // For key-value storage
//   BUCKET: R2Bucket;         // For file storage
//   API_KEY: string;          // For secrets
// } 