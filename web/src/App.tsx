import { useState, useRef, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { AlertCircle, Copy, Download, Eye, EyeOff, Lock, Send, Shield, Timer, QrCode, Upload, FileText, BarChart3 } from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import QRCode from 'qrcode';

export default function VaultifyApp() {
  const [activeTab, setActiveTab] = useState("send");
  const [secret, setSecret] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [ttl, setTtl] = useState("24h");
  const [maxReads, setMaxReads] = useState("1");
  const [retrieveToken, setRetrieveToken] = useState("");
  const [retrievePassword, setRetrievePassword] = useState("");
  const [showRetrievePassword, setShowRetrievePassword] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [qrCodeDataUrl, setQrCodeDataUrl] = useState<string>("");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [useFileUpload, setUseFileUpload] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [storedSecrets, setStoredSecrets] = useState<any[]>([]);

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      setSelectedFile(file);
      const reader = new FileReader();
      reader.onload = (e) => {
        const content = e.target?.result as string;
        setSecret(content);
      };
      reader.readAsText(file);
    }
  };

  const generateQRCode = async (text: string) => {
    try {
      const qrDataUrl = await QRCode.toDataURL(text, {
        width: 200,
        margin: 2,
        color: {
          dark: '#000000',
          light: '#FFFFFF'
        }
      });
      setQrCodeDataUrl(qrDataUrl);
    } catch (error) {
      console.error('Failed to generate QR code:', error);
    }
  };

  const handleSendSecret = async () => {
    let secretToSend = secret;
    
    if (useFileUpload && selectedFile) {
      // In a real implementation, you might want to handle binary files differently
      secretToSend = `File: ${selectedFile.name}\nContent: ${secret}`;
    }
    
    if (!secretToSend.trim() || !password.trim()) {
      setResult({ error: "Secret and password are required" });
      return;
    }

    setLoading(true);
    try {
      // Simulate API call - in real implementation, this would encrypt client-side and send to server
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      const mockToken = `vlt_${Math.random().toString(36).substring(2, 15)}`;
      const expiresAt = new Date(Date.now() + parseTTL(ttl) * 1000);
      const shareUrl = `${window.location.origin}/s/${mockToken}`;
      
      const newSecret = {
        token: mockToken,
        shareUrl,
        expiresAt: expiresAt.toISOString(),
        createdAt: new Date().toISOString(),
        ttl,
        maxReads: parseInt(maxReads),
        isFile: useFileUpload && selectedFile,
        fileName: selectedFile?.name
      };
      
      // Add to stored secrets for dashboard
      setStoredSecrets(prev => [...prev, newSecret]);
      
      // Generate QR code for the share URL
      await generateQRCode(shareUrl);
      
      setResult({
        success: true,
        ...newSecret
      });
    } catch (error) {
      setResult({ error: "Failed to store secret" });
    } finally {
      setLoading(false);
    }
  };

  const handleRetrieveSecret = async () => {
    if (!retrieveToken.trim() || !retrievePassword.trim()) {
      setResult({ error: "Token and password are required" });
      return;
    }

    setLoading(true);
    try {
      // Simulate API call - in real implementation, this would retrieve and decrypt client-side
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      setResult({
        success: true,
        retrievedSecret: "This is your decrypted secret!",
        readsRemaining: 0,
        createdAt: new Date(Date.now() - 3600000).toISOString()
      });
    } catch (error) {
      setResult({ error: "Failed to retrieve secret" });
    } finally {
      setLoading(false);
    }
  };

  const parseTTL = (ttl: string): number => {
    const unit = ttl.slice(-1);
    const value = parseInt(ttl.slice(0, -1));
    switch (unit) {
      case 'm': return value * 60;
      case 'h': return value * 3600;
      case 'd': return value * 86400;
      default: return 86400; // 24h default
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-100 dark:from-slate-900 dark:via-slate-800 dark:to-slate-900">
      {/* Header */}
      <header className="border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="container flex h-14 items-center">
          <div className="flex items-center gap-2">
            <Lock className="h-6 w-6 text-primary" />
            <span className="font-bold text-xl bg-gradient-to-r from-primary to-blue-600 bg-clip-text text-transparent">
              Vaultify
            </span>
          </div>
          <div className="ml-auto flex items-center gap-2">
            <Badge variant="secondary" className="hidden sm:flex">
              <Shield className="h-3 w-3 mr-1" />
              End-to-End Encrypted
            </Badge>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="py-16 text-center">
        <div className="container max-w-4xl">
          <div className="space-y-4">
            <h1 className="text-4xl font-bold tracking-tight sm:text-5xl md:text-6xl">
              Share Secrets
              <span className="bg-gradient-to-r from-primary via-blue-600 to-purple-600 bg-clip-text text-transparent block">
                Securely
              </span>
            </h1>
            <p className="mx-auto max-w-2xl text-lg text-muted-foreground md:text-xl">
              End-to-end encrypted, ephemeral secret sharing with tamper-proof audit logs.
              Your secrets are encrypted before they leave your device.
            </p>
          </div>

          {/* Security Features */}
          <div className="mt-12 grid grid-cols-1 gap-4 sm:grid-cols-3">
            <div className="flex items-center gap-3 rounded-lg border p-4">
              <Lock className="h-8 w-8 text-green-500" />
              <div className="text-left">
                <div className="font-medium">AES-256-GCM</div>
                <div className="text-sm text-muted-foreground">Military-grade encryption</div>
              </div>
            </div>
            <div className="flex items-center gap-3 rounded-lg border p-4">
              <Timer className="h-8 w-8 text-blue-500" />
              <div className="text-left">
                <div className="font-medium">Auto-Expire</div>
                <div className="text-sm text-muted-foreground">Configurable TTL</div>
              </div>
            </div>
            <div className="flex items-center gap-3 rounded-lg border p-4">
              <Eye className="h-8 w-8 text-purple-500" />
              <div className="text-left">
                <div className="font-medium">Read Once</div>
                <div className="text-sm text-muted-foreground">Self-destructing secrets</div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Main Interface */}
      <section className="pb-16">
        <div className="container max-w-4xl">
          <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
            <TabsList className="grid w-full grid-cols-3 mb-8">
              <TabsTrigger value="send" className="gap-2">
                <Send className="h-4 w-4" />
                Send Secret
              </TabsTrigger>
              <TabsTrigger value="retrieve" className="gap-2">
                <Download className="h-4 w-4" />
                Retrieve Secret
              </TabsTrigger>
              <TabsTrigger value="dashboard" className="gap-2">
                <BarChart3 className="h-4 w-4" />
                Dashboard
              </TabsTrigger>
            </TabsList>

            {/* Send Secret Tab */}
            <TabsContent value="send">
              <Card>
                <CardHeader>
                  <CardTitle>Send a Secret</CardTitle>
                  <CardDescription>
                    Your secret will be encrypted in your browser before being sent to the server.
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                  <div className="space-y-4">
                    <div className="flex items-center gap-4">
                      <Label htmlFor="secret">Secret *</Label>
                      <div className="flex items-center gap-2">
                        <Button
                          type="button"
                          variant={useFileUpload ? "secondary" : "outline"}
                          size="sm"
                          onClick={() => setUseFileUpload(!useFileUpload)}
                          className="gap-2"
                        >
                          <Upload className="h-3 w-3" />
                          {useFileUpload ? "Using File" : "Upload File"}
                        </Button>
                        {useFileUpload && (
                          <Button
                            type="button"
                            variant="outline"
                            size="sm"
                            onClick={() => fileInputRef.current?.click()}
                            className="gap-2"
                          >
                            <FileText className="h-3 w-3" />
                            Choose File
                          </Button>
                        )}
                      </div>
                    </div>
                    
                    {useFileUpload ? (
                      <div className="space-y-2">
                        <input
                          ref={fileInputRef}
                          type="file"
                          onChange={handleFileUpload}
                          className="hidden"
                          accept=".txt,.json,.csv,.md,.log"
                        />
                        {selectedFile ? (
                          <div className="rounded-lg border p-4">
                            <div className="flex items-center gap-2 mb-2">
                              <FileText className="h-4 w-4" />
                              <span className="font-medium">{selectedFile.name}</span>
                              <Badge variant="secondary">{(selectedFile.size / 1024).toFixed(1)} KB</Badge>
                            </div>
                            <div className="text-sm text-muted-foreground mb-2">File preview:</div>
                            <Textarea
                              value={secret}
                              onChange={(e) => setSecret(e.target.value)}
                              className="min-h-[100px] resize-none font-mono text-sm"
                              readOnly={false}
                            />
                          </div>
                        ) : (
                          <div className="rounded-lg border-2 border-dashed border-muted p-8 text-center">
                            <Upload className="h-8 w-8 mx-auto mb-2 text-muted-foreground" />
                            <p className="text-sm text-muted-foreground">Click "Choose File" to upload a text file</p>
                            <p className="text-xs text-muted-foreground mt-1">Supports: .txt, .json, .csv, .md, .log</p>
                          </div>
                        )}
                      </div>
                    ) : (
                      <Textarea
                        id="secret"
                        placeholder="Enter your secret here (passwords, API keys, sensitive data...)"
                        value={secret}
                        onChange={(e) => setSecret(e.target.value)}
                        className="min-h-[100px] resize-none"
                      />
                    )}
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="password">Encryption Password *</Label>
                    <div className="relative">
                      <Input
                        id="password"
                        type={showPassword ? "text" : "password"}
                        placeholder="Strong password for encryption"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                      />
                      <Button
                        type="button"
                        variant="ghost"
                        size="sm"
                        className="absolute right-0 top-0 h-full px-3 hover:bg-transparent"
                        onClick={() => setShowPassword(!showPassword)}
                      >
                        {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                      </Button>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                    <div className="space-y-2">
                      <Label htmlFor="ttl">Time to Live</Label>
                      <Input
                        id="ttl"
                        placeholder="24h"
                        value={ttl}
                        onChange={(e) => setTtl(e.target.value)}
                      />
                      <p className="text-xs text-muted-foreground">Examples: 30m, 2h, 1d</p>
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="maxReads">Max Reads</Label>
                      <Input
                        id="maxReads"
                        placeholder="1"
                        value={maxReads}
                        onChange={(e) => setMaxReads(e.target.value)}
                      />
                      <p className="text-xs text-muted-foreground">0 = unlimited</p>
                    </div>
                  </div>

                  <Button 
                    onClick={handleSendSecret} 
                    disabled={loading || !secret.trim() || !password.trim()}
                    className="w-full gap-2"
                    size="lg"
                  >
                    <Lock className="h-4 w-4" />
                    {loading ? "Encrypting & Storing..." : "Send Secret"}
                  </Button>

                  {result && result.success && (
                    <Alert className="border-green-200 bg-green-50 dark:border-green-800 dark:bg-green-950">
                      <AlertCircle className="h-4 w-4 text-green-600" />
                      <AlertDescription className="space-y-4">
                        <div className="font-medium text-green-800 dark:text-green-200">
                          ✅ Secret stored successfully!
                        </div>
                        
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <div className="space-y-2">
                            <div className="flex items-center gap-2">
                              <Label className="text-sm font-medium">Token:</Label>
                              <code className="rounded bg-muted px-2 py-1 text-sm">{result.token}</code>
                              <Button size="sm" variant="ghost" onClick={() => copyToClipboard(result.token)}>
                                <Copy className="h-3 w-3" />
                              </Button>
                            </div>
                            <div className="flex items-center gap-2">
                              <Label className="text-sm font-medium">Share URL:</Label>
                              <code className="rounded bg-muted px-2 py-1 text-sm truncate">{result.shareUrl}</code>
                              <Button size="sm" variant="ghost" onClick={() => copyToClipboard(result.shareUrl)}>
                                <Copy className="h-3 w-3" />
                              </Button>
                            </div>
                            <div className="text-sm text-muted-foreground">
                              Expires: {new Date(result.expiresAt).toLocaleString()}
                            </div>
                            {result.isFile && (
                              <div className="text-sm text-muted-foreground">
                                📄 File: {result.fileName}
                              </div>
                            )}
                          </div>
                          
                          {qrCodeDataUrl && (
                            <div className="flex flex-col items-center space-y-2">
                              <Label className="text-sm font-medium flex items-center gap-1">
                                <QrCode className="h-3 w-3" />
                                QR Code for Mobile
                              </Label>
                              <img 
                                src={qrCodeDataUrl} 
                                alt="QR Code for secret sharing" 
                                className="rounded border" 
                              />
                              <p className="text-xs text-muted-foreground text-center">
                                Scan to access on mobile
                              </p>
                            </div>
                          )}
                        </div>
                      </AlertDescription>
                    </Alert>
                  )}

                  {result && result.error && (
                    <Alert variant="destructive">
                      <AlertCircle className="h-4 w-4" />
                      <AlertDescription>{result.error}</AlertDescription>
                    </Alert>
                  )}
                </CardContent>
              </Card>
            </TabsContent>

            {/* Retrieve Secret Tab */}
            <TabsContent value="retrieve">
              <Card>
                <CardHeader>
                  <CardTitle>Retrieve a Secret</CardTitle>
                  <CardDescription>
                    Enter the token and password to decrypt and retrieve your secret.
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                  <div className="space-y-2">
                    <Label htmlFor="retrieveToken">Token *</Label>
                    <Input
                      id="retrieveToken"
                      placeholder="Enter the secret token"
                      value={retrieveToken}
                      onChange={(e) => setRetrieveToken(e.target.value)}
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="retrievePassword">Decryption Password *</Label>
                    <div className="relative">
                      <Input
                        id="retrievePassword"
                        type={showRetrievePassword ? "text" : "password"}
                        placeholder="Password used for encryption"
                        value={retrievePassword}
                        onChange={(e) => setRetrievePassword(e.target.value)}
                      />
                      <Button
                        type="button"
                        variant="ghost"
                        size="sm"
                        className="absolute right-0 top-0 h-full px-3 hover:bg-transparent"
                        onClick={() => setShowRetrievePassword(!showRetrievePassword)}
                      >
                        {showRetrievePassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                      </Button>
                    </div>
                  </div>

                  <Button 
                    onClick={handleRetrieveSecret} 
                    disabled={loading || !retrieveToken.trim() || !retrievePassword.trim()}
                    className="w-full gap-2"
                    size="lg"
                  >
                    <Download className="h-4 w-4" />
                    {loading ? "Retrieving & Decrypting..." : "Retrieve Secret"}
                  </Button>

                  {result && result.success && result.retrievedSecret && (
                    <Alert className="border-green-200 bg-green-50 dark:border-green-800 dark:bg-green-950">
                      <AlertCircle className="h-4 w-4 text-green-600" />
                      <AlertDescription className="space-y-3">
                        <div className="font-medium text-green-800 dark:text-green-200">
                          ✅ Secret retrieved successfully!
                        </div>
                        <div className="space-y-2">
                          <div className="rounded bg-muted p-3">
                            <Label className="text-sm font-medium">Your Secret:</Label>
                            <div className="mt-1 font-mono text-sm break-all">{result.retrievedSecret}</div>
                          </div>
                          <div className="text-sm text-muted-foreground">
                            {result.readsRemaining === 0 ? (
                              "⚠️ This secret has been deleted after retrieval."
                            ) : (
                              `📊 Reads remaining: ${result.readsRemaining}`
                            )}
                          </div>
                          <div className="text-sm text-muted-foreground">
                            Created: {new Date(result.createdAt).toLocaleString()}
                          </div>
                        </div>
                      </AlertDescription>
                    </Alert>
                  )}

                  {result && result.error && (
                    <Alert variant="destructive">
                      <AlertCircle className="h-4 w-4" />
                      <AlertDescription>{result.error}</AlertDescription>
                    </Alert>
                  )}
                </CardContent>
              </Card>
            </TabsContent>

            {/* Dashboard Tab */}
            <TabsContent value="dashboard">
              <Card>
                <CardHeader>
                  <CardTitle>Secrets Dashboard</CardTitle>
                  <CardDescription>
                    View and manage your stored secrets. This dashboard shows secrets created in this session.
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  {storedSecrets.length === 0 ? (
                    <div className="text-center py-8">
                      <BarChart3 className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                      <h3 className="font-medium mb-2">No secrets stored yet</h3>
                      <p className="text-sm text-muted-foreground mb-4">
                        Secrets you create will appear here for easy management.
                      </p>
                      <Button onClick={() => setActiveTab("send")} variant="outline">
                        Create Your First Secret
                      </Button>
                    </div>
                  ) : (
                    <div className="space-y-4">
                      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                        <Card>
                          <CardContent className="p-4">
                            <div className="text-2xl font-bold">{storedSecrets.length}</div>
                            <div className="text-sm text-muted-foreground">Total Secrets</div>
                          </CardContent>
                        </Card>
                        <Card>
                          <CardContent className="p-4">
                            <div className="text-2xl font-bold">
                              {storedSecrets.filter(s => new Date(s.expiresAt) > new Date()).length}
                            </div>
                            <div className="text-sm text-muted-foreground">Active Secrets</div>
                          </CardContent>
                        </Card>
                        <Card>
                          <CardContent className="p-4">
                            <div className="text-2xl font-bold">
                              {storedSecrets.filter(s => s.isFile).length}
                            </div>
                            <div className="text-sm text-muted-foreground">File Secrets</div>
                          </CardContent>
                        </Card>
                      </div>
                      
                      <div className="space-y-3">
                        <h3 className="font-medium">Recent Secrets</h3>
                        {storedSecrets.slice().reverse().map((secret, index) => {
                          const isExpired = new Date(secret.expiresAt) <= new Date();
                          const timeUntilExpiry = new Date(secret.expiresAt).getTime() - new Date().getTime();
                          const hoursLeft = Math.max(0, Math.floor(timeUntilExpiry / (1000 * 60 * 60)));
                          
                          return (
                            <Card key={index} className={isExpired ? "opacity-50" : ""}>
                              <CardContent className="p-4">
                                <div className="flex items-start justify-between">
                                  <div className="space-y-1">
                                    <div className="flex items-center gap-2">
                                      <code className="text-sm bg-muted px-2 py-1 rounded">
                                        {secret.token}
                                      </code>
                                      {secret.isFile && (
                                        <Badge variant="secondary" className="gap-1">
                                          <FileText className="h-3 w-3" />
                                          {secret.fileName}
                                        </Badge>
                                      )}
                                      {isExpired ? (
                                        <Badge variant="destructive">Expired</Badge>
                                      ) : (
                                        <Badge variant="secondary">
                                          {hoursLeft}h remaining
                                        </Badge>
                                      )}
                                    </div>
                                    <div className="text-sm text-muted-foreground">
                                      Created: {new Date(secret.createdAt).toLocaleString()}
                                    </div>
                                    <div className="text-sm text-muted-foreground">
                                      TTL: {secret.ttl} • Max reads: {secret.maxReads === 0 ? 'unlimited' : secret.maxReads}
                                    </div>
                                  </div>
                                  <div className="flex gap-2">
                                    <Button 
                                      size="sm" 
                                      variant="ghost" 
                                      onClick={() => copyToClipboard(secret.shareUrl)}
                                      disabled={isExpired}
                                    >
                                      <Copy className="h-3 w-3" />
                                    </Button>
                                    <Button 
                                      size="sm" 
                                      variant="ghost" 
                                      onClick={() => {
                                        generateQRCode(secret.shareUrl);
                                        setResult({ success: true, ...secret });
                                      }}
                                      disabled={isExpired}
                                    >
                                      <QrCode className="h-3 w-3" />
                                    </Button>
                                  </div>
                                </div>
                              </CardContent>
                            </Card>
                          );
                        })}
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t bg-muted/50">
        <div className="container py-8">
          <div className="text-center text-sm text-muted-foreground">
            <p className="mb-2">
              <strong>🔐 Vaultify</strong> - Zero-knowledge secret sharing with end-to-end encryption
            </p>
            <p>
              Your secrets are encrypted in your browser before transmission. The server never sees your plaintext data.
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}
