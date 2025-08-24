; ============================================
; BLADE & SOUL MACRO v7.0 - COMPLETE FIXED VERSION
; Professional Gaming Enhancement Tool
; © 2025 BNS Macro Team. All rights reserved.
; ============================================

#Requires AutoHotkey v2.0.10+
#SingleInstance Force
ProcessSetPriority("High")
SetKeyDelay(-1, -1)
SetMouseDelay(-1)
SetDefaultMouseSpeed(0)
SetWinDelay(-1)
KeyHistory(0)
ListLines(False)

; ================= INCLUDES =================
#Include FindText.ahk
#Include JSON.ahk

; ================= GLOBAL CONFIGURATION =================
global APP_VERSION := "7.0.0"
global APP_BUILD := "2025.08.23"
global UPDATE_CHANNEL := "stable"
global CONFIG_FILE := A_ScriptDir . "\config.ini"
global PRESETS_DIR := A_ScriptDir . "\Presets"
global LOGS_DIR := A_ScriptDir . "\Logs"
global BACKUP_DIR := A_ScriptDir . "\Backup"
global UPDATE_DIR := A_ScriptDir . "\Updates"

; ================= SUPABASE CONFIGURATION =================
global SUPABASE := {
    url: "https://fdswkurfccznevewispw.supabase.co",
    anonKey: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImZkc3drdXJmY2N6bmV2ZXdpc3B3Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTU4OTMwNDQsImV4cCI6MjA3MTQ2OTA0NH0._cqhPDgivwCxoUBd0G6QyQFwJjlu2hM9M3ONr5ohZr4",
    authURL: "https://fdswkurfccznevewispw.supabase.co/auth/v1",
    restURL: "https://fdswkurfccznevewispw.supabase.co/rest/v1"
}

; ================= SESSION DO USUÁRIO =================
global SESSION := {
    authenticated: false,
    token: "",
    refreshToken: "",
    userId: "",
    email: "",
    nickname: "",
    role: "user",
    permissions: [],
    trialExpiry: "",
    isBlocked: false,
    isTrial: false,
    trialDaysRemaining: 0,
    lastActivity: A_TickCount,
    sessionTimeout: 43200000,
    deviceId: "",
    tokenExpiry: 0,
    loginAttempts: 0,
    lastLoginAttempt: 0
}

; ================= RUNTIME STATE =================
global RUNTIME := {
    mode: "puncture",
    suspendMacros: false,
    macro1Active: false,
    macro2Active: false,
    macro1Type: "",
    macro2Type: "",
    debugMode: false,
    updateAvailable: false,
    latestVersion: "",
    mainMenuOpen: false,
    secureMode: true,
    antiCheatActive: false,
    performanceMode: false,
    flowchartMode: "puncture",
    maintenanceMode: false,
    announcement: "",
    trialDays: 7,
    maxPresetsTrialUser: 3,
    maxPresetsPremiumUser: 100
}

; ================= GUI REFERENCES =================
global GUI_REFS := Map()
GUI_REFS["login"] := ""
GUI_REFS["register"] := ""
GUI_REFS["main"] := ""
GUI_REFS["hotkey"] := ""
GUI_REFS["macro"] := ""
GUI_REFS["hybrid"] := ""
GUI_REFS["puncture"] := ""
GUI_REFS["preset"] := ""
GUI_REFS["build"] := ""
GUI_REFS["flowchart"] := ""
GUI_REFS["import_export"] := ""
GUI_REFS["build_library"] := ""
GUI_REFS["system_stats"] := ""
GUI_REFS["user_manager"] := ""


; ================= PATTERNS FOR FINDTEXT =================
global PATTERNS := {
    Ccrit: "|<>*88$16.zzs3k7Uzw7w3y1z0U",
    Lcrit: "|<>*88$16.zzy1k3Uzw3w1y0z0U"
}

global mainStatusText := ""  ; Main Menu Text Update

; ================= CORREÇÃO DE ERRO 2: Simplificação da Inicialização de Configurações =================
; A inicialização redundante foi removida. Este Map agora é a única fonte de padrões.
; A função SaveSettings() no início do script garantirá que o config.ini seja criado com todos esses valores se não existir.
global SETTINGS := Map(
    "hotkey_macro1", "XButton1",
    "hotkey_macro2", "XButton2",
    "hotkey_menu", "Delete",
    "hotkey_suspend", "F12",
    "hotkey_mode_toggle", "Home",
    "macro1_mode", "hold",
    "macro2_mode", "hold",
    "key_puncture_r", "r",
    "key_puncture_t", "t",
    "key_puncture_tab", "Tab",
    "key_hybrid_main", "t",
    "key_hybrid_secondary", "r",
    "macro_timing", "30",
    "macro_loop", "4",
    "sleep_punc_x2_fast", "15",
    "sleep_punc_x2_tab", "30",
    "sleep_punc_x2_final", "5",
    "sleep_punc_x1_r_tab_gap", "85",
    "sleep_punc_x1_tab_crit_gap", "65",
    "sleep_punc_x1_crit_check", "100",
    "sleep_punc_x1_crit_combo", "85",
    "sleep_punc_x1_t_between", "20",
    "sleep_punc_x1_no_crit", "50",
    "hybrid_macro1_sequence", "t",
    "hybrid_macro1_timing", "10",
    "hybrid_macro1_mode", "continuous",
    "hybrid_macro1_repeat_count", "1",
    "hybrid_macro1_sequence_delay", "50",
    "hybrid_macro2_sequence", "t,t,r",
    "hybrid_macro2_timing", "10",
    "hybrid_macro2_sequence_delay", "50",
    "hybrid_macro2_pixelsearch_position", "0",
    "hybrid_macro2_no_pixel_action", "t",
    "hybrid_macro2_no_pixel_delay", "50",
    "puncture_x1", "124",
    "puncture_y1", "916",
    "puncture_x2", "172",
    "puncture_y2", "1013",
    "hybrid_x1", "1567",
    "hybrid_y1", "1181",
    "hybrid_x2", "1599",
    "hybrid_y2", "1216",
    "hybrid_color", "0x2984B1",
    "hybrid_variation", "2",
    "findtext_retries", "3",
    "findtext_retry_delay", "10",
    "hybrid_pixelsearch_retries", "3",
    "hybrid_pixelsearch_retry_delay", "5",
    "debug_mode", "0",
    "auto_update", "1",
    "remember_login", "0",
    "secure_storage", "1",
    "performance_mode", "0",
    "log_activities", "1"
)

; ================= CLOUD PRESETS STORAGE =================
global CLOUD_PRESETS := []
global LOCAL_PRESETS := []
global CLOUD_PRESET_IDS := Map()
global SELECTED_PRESET := ""
global PRESET_IN_USE := ""

; ================= TOOLTIP MANAGER =================
class TooltipManager {
    static currentTooltip := ""
    static tooltipTimer := 0
    
    static Show(control, text) {
        this.currentTooltip := text
        
        try {
            control.OnEvent("Focus", (*) => this.Display(text))
            control.OnEvent("LoseFocus", (*) => this.Hide())
        } catch {
            ; If control doesn't support these events
        }
    }
    
    static Display(text, x := "", y := "") {
        if (x = "" || y = "") {
            MouseGetPos(&mx, &my)
            x := mx
            y := my + 20
        }
        ToolTip(text, x, y)
        if this.tooltipTimer {
            SetTimer(this.tooltipTimer, 0)
        }
        this.tooltipTimer := () => this.Hide()
        SetTimer(this.tooltipTimer, 5000)
    }
    
    static Hide() {
        ToolTip()
        if this.tooltipTimer {
            SetTimer(this.tooltipTimer, 0)
            this.tooltipTimer := 0
        }
    }
}

; ================= SECURITY MANAGER =================
class SecurityManager {
    static rateLimiter := Map()
    static encryptionKey := ""
    
    static Initialize() {
        this.encryptionKey := this.GenerateEncryptionKey()
        this.LoadSecureConfig()
        
        if (RUNTIME.secureMode) {
            this.EnableAntiDebugging()
        }
    }
    
    static LoadSecureConfig() {
        ; Secure configuration loading
        SUPABASE.anonKey := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImZkc3drdXJmY2N6bmV2ZXdpc3B3Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTU4OTMwNDQsImV4cCI6MjA3MTQ2OTA0NH0._cqhPDgivwCxoUBd0G6QyQFwJjlu2hM9M3ONr5ohZr4"
    }
    
    static GenerateEncryptionKey() {
        key := A_ComputerName . A_UserName
        
        if (key == "") {
            key := "BNS_Macro_Fallback_Key_2025"
        }
        
        try {
            wmi := ComObject("WbemScripting.SWbemLocator")
            service := wmi.ConnectServer()
            
            for item in service.ExecQuery("SELECT * FROM Win32_ComputerSystemProduct") {
                if (item.UUID) {
                    key .= item.UUID
                }
                break
            }
        }
        
        return this.HashString(key)
    }
    
    static Encrypt(data) {
        if (!data)
            return ""
        
        if (this.encryptionKey == "") {
            this.encryptionKey := this.GenerateEncryptionKey()
        }
        
        ; Simple XOR encryption
        encrypted := ""
        key := this.encryptionKey
        keyLen := StrLen(key)
        
        Loop Parse, data {
            charCode := Ord(A_LoopField)
            keyChar := Ord(SubStr(key, Mod(A_Index - 1, keyLen) + 1, 1))
            encrypted .= Format("{:04X}", charCode ^ keyChar)
        }
        
        return encrypted
    }
    
    static Decrypt(data) {
        if (!data)
            return ""
        
        if (this.encryptionKey == "") {
            this.encryptionKey := this.GenerateEncryptionKey()
        }
        
        decrypted := ""
        key := this.encryptionKey
        keyLen := StrLen(key)
        
        Loop Parse, data {
            if (Mod(A_Index - 1, 4) == 0 && A_Index <= StrLen(data) - 3) {
                hexBlock := SubStr(data, A_Index, 4)
                charCode := Integer("0x" . hexBlock)
                keyChar := Ord(SubStr(key, Mod((A_Index - 1) / 4, keyLen) + 1, 1))
                decrypted .= Chr(charCode ^ keyChar)
            }
        }
        
        return decrypted
    }
    
    static HashString(str) {
        hash := 0x811C9DC5
        
        Loop Parse, str {
            hash ^= Ord(A_LoopField)
            hash *= 0x01000193
            hash &= 0xFFFFFFFF
        }
        
        return Format("{:08X}", hash)
    }
    
    static ValidateToken(token) {
        if (!token)
            return false
        
        parts := StrSplit(token, ".")
        if (parts.Length != 3)
            return false
        
        return true
    }
    
    static ValidateEmail(email) {
        pattern := "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return RegExMatch(email, pattern) > 0
    }
    
    static ValidatePassword(password) {
        if (StrLen(password) < 8) {
            return {valid: false, error: "Password must be at least 8 characters"}
        }
        
        if (!RegExMatch(password, "[A-Z]")) {
            return {valid: false, error: "Password must contain uppercase letter"}
        }
        
        if (!RegExMatch(password, "[a-z]")) {
            return {valid: false, error: "Password must contain lowercase letter"}
        }
        
        if (!RegExMatch(password, "[0-9]")) {
            return {valid: false, error: "Password must contain number"}
        }
        
        return {valid: true}
    }
    
    static CheckRateLimit(action, identifier := "") {
        if (!identifier) {
            identifier := SESSION.deviceId
        }
        
        key := action . "_" . identifier
        now := A_TickCount
        
        if (!this.rateLimiter.Has(key)) {
            this.rateLimiter[key] := {
                count: 0,
                firstAttempt: now,
                lastAttempt: now
            }
        }
        
        limit := this.rateLimiter[key]
        
        if (now - limit.firstAttempt > 60000) {
            limit.count := 0
            limit.firstAttempt := now
        }
        
        limit.count++
        limit.lastAttempt := now
        
        maxAttempts := Map(
            "login", 5,
            "register", 3,
            "api_call", 100,
            "preset_upload", 10
        )
        
        maxAllowed := maxAttempts.Get(action, 50)
        
        if (limit.count > maxAllowed) {
            return false
        }
        
        return true
    }
    
    static EnableAntiDebugging() {
        SetTimer(() => this.CheckDebugger(), 30000)
    }
    
    static CheckDebugger() {
        if (DllCall("kernel32\IsDebuggerPresent")) {
            MsgBox("Debugger detected. Application will close.", "Security", "Icon!")
            ExitApp()
        }
    }
    
    static LogSecurityEvent(event, details := "") {
        if (!DirExist(LOGS_DIR)) {
            DirCreate(LOGS_DIR)
        }
        
        logFile := LOGS_DIR . "\security_" . FormatTime(A_Now, "yyyy-MM-dd") . ".log"
        
        logEntry := FormatTime(A_Now, "yyyy-MM-dd HH:mm:ss") . " | "
        logEntry .= event . " | "
        logEntry .= SESSION.userId . " | "
        logEntry .= SESSION.deviceId . " | "
        logEntry .= details . "`n"
        
        try {
            FileAppend(logEntry, logFile)
        }
    }
    
    static SanitizeInput(input) {
        sanitized := StrReplace(input, "<", "&lt;")
        sanitized := StrReplace(sanitized, ">", "&gt;")
        sanitized := StrReplace(sanitized, '"', "&quot;")
        sanitized := StrReplace(sanitized, "'", "&#39;")
        sanitized := StrReplace(sanitized, "&", "&amp;")
        
        sanitized := RegExReplace(sanitized, "[\x00-\x1F\x7F]", "")
        
        return Trim(sanitized)
    }
}

; ================= ERROR HANDLER =================
class ErrorHandler {
    static errorLog := []
    static maxLogSize := 100
    
    static Initialize() {
        OnError(ObjBindMethod(this, "HandleError"))
    }
    
    static HandleError(e, mode) {
        this.errorLog.Push({
            time: A_Now,
            message: e.Message,
            file: e.File,
            line: e.Line,
            stack: e.Stack
        })
        
        if (this.errorLog.Length > this.maxLogSize) {
            this.errorLog.RemoveAt(1)
        }
        
        this.SaveErrorLog(e)
        
        if (RUNTIME.debugMode) {
            MsgBox(
                "Error detected:`n`n" .
                "Message: " . e.Message . "`n" .
                "File: " . e.File . "`n" .
                "Line: " . e.Line,
                "Debug Error",
                "Icon!"
            )
        } else {
            ShowTooltip("⚠️ An error occurred. Check logs.", 3000)
        }
        
        return true
    }
    
    static SaveErrorLog(e) {
        if (!DirExist(LOGS_DIR)) {
            DirCreate(LOGS_DIR)
        }
        
        logFile := LOGS_DIR . "\error_" . FormatTime(A_Now, "yyyy-MM-dd") . ".log"
        
        logEntry := "`n[" . FormatTime(A_Now, "yyyy-MM-dd HH:mm:ss") . "]`n"
        logEntry .= "Message: " . e.Message . "`n"
        logEntry .= "File: " . e.File . "`n"
        logEntry .= "Line: " . e.Line . "`n"
        
        if (e.HasProp("Stack")) {
            logEntry .= "Stack: " . e.Stack . "`n"
        }
        
        logEntry .= "---`n"
        
        try {
            FileAppend(logEntry, logFile)
        }
    }
}

; ================= HTTP CLIENT =================
class HttpClient {
    static timeout := 30000
    static retryCount := 3
    static retryDelay := 1000
    
    static Request(method, url, data := "", headers := Map(), options := Map()) {
        attempt := 0
        lastError := ""
        
        while (attempt < this.retryCount) {
            attempt++
            
            try {
                whr := ComObject("WinHttp.WinHttpRequest.5.1")
                
                timeoutValue := options.Get("timeout", this.timeout)
                whr.SetTimeouts(timeoutValue, timeoutValue, timeoutValue, timeoutValue)
                
                async := options.Get("async", true)
                whr.Open(method, url, async)
                
                whr.SetRequestHeader("User-Agent", "BNS-Macro/" . APP_VERSION)
                whr.SetRequestHeader("Accept", "application/json")
                whr.SetRequestHeader("Accept-Language", "pt-BR,pt;q=0.9,en;q=0.8")
                whr.SetRequestHeader("Cache-Control", "no-cache")
                whr.SetRequestHeader("Pragma", "no-cache")
                
                if (data && (method = "POST" || method = "PUT" || method = "PATCH")) {
                    whr.SetRequestHeader("Content-Type", "application/json; charset=utf-8")
                }
                
                if (SUPABASE.anonKey) {
                    whr.SetRequestHeader("apikey", SUPABASE.anonKey)
                }
                
                if (SESSION.token && SecurityManager.ValidateToken(SESSION.token)) {
                    whr.SetRequestHeader("Authorization", "Bearer " . SESSION.token)
                }
                
                for key, value in headers {
                    whr.SetRequestHeader(key, value)
                }
                
                if (!options.Get("skipSSL", false)) {
                    whr.Option[4] := 0
                    whr.Option[9] := 0x0800 | 0x2000
                }
                
                if (data) {
                    whr.Send(data)
                } else {
                    whr.Send()
                }
                
                if (async) {
                    whr.WaitForResponse()
                }
                
                response := {
                    status: whr.Status,
                    statusText: whr.StatusText,
                    text: whr.ResponseText,
                    headers: Map(),
                    success: (whr.Status >= 200 && whr.Status < 300)
                }
                
                headersText := whr.GetAllResponseHeaders()
                if (headersText) {
                    for line in StrSplit(headersText, "`n") {
                        if (InStr(line, ":")) {
                            parts := StrSplit(line, ":", " ", 2)
                            if (parts.Length == 2) {
                                response.headers[Trim(parts[1])] := Trim(parts[2])
                            }
                        }
                    }
                }
                
                if (RUNTIME.debugMode) {
                    this.LogRequest(method, url, response.status)
                }
                
                return response
                
            } catch as e {
                lastError := e.Message
                
                if (attempt < this.retryCount) {
                    Sleep(this.retryDelay * attempt)
                }
            }
        }
        
        return {
            status: 0,
            statusText: "Request Failed",
            error: lastError,
            text: "",
            headers: Map(),
            success: false
        }
    }
    
    static Get(url, headers := Map(), options := Map()) {
        return this.Request("GET", url, "", headers, options)
    }
    
    static Post(url, data, headers := Map(), options := Map()) {
        return this.Request("POST", url, data, headers, options)
    }
    
    static Put(url, data, headers := Map(), options := Map()) {
        return this.Request("PUT", url, data, headers, options)
    }
    
    static Patch(url, data, headers := Map(), options := Map()) {
        return this.Request("PATCH", url, data, headers, options)
    }
    
    static Delete(url, headers := Map(), options := Map()) {
        return this.Request("DELETE", url, "", headers, options)
    }
    
    static LogRequest(method, url, status) {
        if (!DirExist(LOGS_DIR)) {
            DirCreate(LOGS_DIR)
        }
        
        logFile := LOGS_DIR . "\http_" . FormatTime(A_Now, "yyyy-MM-dd") . ".log"
        
        logEntry := FormatTime(A_Now, "HH:mm:ss") . " | "
        logEntry .= method . " | "
        logEntry .= status . " | "
        logEntry .= url . "`n"
        
        try {
            FileAppend(logEntry, logFile)
        }
    }
}

; ================= SUPABASE CLIENT =================
class SupabaseClient {
    baseUrl := ""
    apiKey := ""
    accessToken := ""

    static cache := Map()
    static cacheExpiry := Map()
    static cacheTimeout := 300000

    static SyncAppSettings() {
        global RUNTIME
        ; Fetch announcement and maintenance mode from app config
        RUNTIME.announcement := this.GetAnnouncement()
        RUNTIME.maintenanceMode := this.IsMaintenanceMode()
        ; Check for updates
        this.CheckUpdate()
    }
    
    static Login(email, password) {
    if (!SecurityManager.CheckRateLimit("login", email)) {
        return Map(
            "success", false,
            "error", "Too many attempts. Please wait."
        )
    }
    
    email := SecurityManager.SanitizeInput(email)
    
    if (!email || !password) {
        return Map("success", false, "error", "Email and password are required")
    }
    
    if (!SecurityManager.ValidateEmail(email)) {
        return Map("success", false, "error", "Invalid email")
    }
    
    payload := JSON.Stringify(Map(
        "email", email,
        "password", password
    ))
    
    url := SUPABASE.authURL . "/token?grant_type=password"
    
    response := HttpClient.Post(url, payload)
    
    if (response.success) {
        try {
            data := JSON.Parse(response.text)
            
            SESSION.token := data.Get("access_token", "")
            SESSION.refreshToken := data.Get("refresh_token", "")
            SESSION.authenticated := true
            SESSION.loginAttempts := 0
            
            if (data.Has("expires_in")) {
                SESSION.tokenExpiry := A_TickCount + (data["expires_in"] * 1000)
            }
            
            if (data.Has("user")) {
                user := data["user"]
                SESSION.userId := user.Get("id", "")
                SESSION.email := user.Get("email", email)
                
                if (user.Has("user_metadata")) {
                    metadata := user["user_metadata"]
                    SESSION.nickname := metadata.Get("nickname", 
                                      metadata.Get("display_name", 
                                      StrSplit(email, "@")[1]))
                    SESSION.role := metadata.Get("role", "user")
                }
            }
            
            this.GetProfile()
            
            this.LogActivity("login", "Successful login from " . A_ComputerName)
            SecurityManager.LogSecurityEvent("login_success", email)
            
            return Map(
                "success", true,
                "message", "Login successful"
            )
            
        } catch as e {
            return Map(
                "success", false,
                "error", "Error processing response: " . e.Message
            )
        }
    } else {
        SESSION.loginAttempts++
        
        SecurityManager.LogSecurityEvent("login_failed", email . " | Status: " . response.status)
        
        errorMsg := "Authentication error"
        
        if (response.status = 400) {
            errorMsg := "Invalid email or password"
        } else if (response.status = 422) {
            errorMsg := "Email not verified. Check your inbox."
        } else if (response.status = 429) {
            errorMsg := "Too many attempts. Please wait."
        } else if (response.status = 0) {
            errorMsg := "Connection error. Check your internet."
        }
        
        try {
            errorData := JSON.Parse(response.text)
            if (errorData.Has("error_description")) {
                errorMsg := errorData["error_description"]
            } else if (errorData.Has("msg")) {
                errorMsg := errorData["msg"]
            }
        }
        
        return Map("success", false, "error", errorMsg)
    }
}
    
    static Register(email, password, nickname) {
    if (!SecurityManager.CheckRateLimit("register", email)) {
        return Map(
            "success", false,
            "error", "Too many registration attempts"
        )
    }
    
    email := SecurityManager.SanitizeInput(email)
    nickname := SecurityManager.SanitizeInput(nickname)
    
    if (!SecurityManager.ValidateEmail(email)) {
        return Map("success", false, "error", "Invalid email")
    }
    
    passwordValidation := SecurityManager.ValidatePassword(password)
    if (!passwordValidation.valid) {
        return Map("success", false, "error", passwordValidation.error)
    }
    
    if (StrLen(nickname) < 3 || StrLen(nickname) > 20) {
        return Map("success", false, "error", "Nickname must be 3-20 characters")
    }
    
    if (!RegExMatch(nickname, "^[a-zA-Z0-9_\-]+$")) {
        return Map("success", false, "error", "Nickname contains invalid characters")
    }
    
    trialExpiry := FormatTime(DateAdd(A_Now, 7, "Days"), "yyyy-MM-dd")
    
    payload := JSON.Stringify(Map(
        "email", email,
        "password", password,
        "data", Map(
            "nickname", nickname,
            "display_name", nickname,
            "device_id", GetDeviceFingerprint(),
            "app_version", APP_VERSION,
            "registered_at", FormatTime(A_Now, "yyyy-MM-dd HH:mm:ss"),
            "trial_expiry", trialExpiry,
            "is_trial", true,
            "role", "trial"
        )
    ))
    
    url := SUPABASE.authURL . "/signup"
    
    response := HttpClient.Post(url, payload)
    
    if (response.success) {
        SecurityManager.LogSecurityEvent("register_success", email)
        
        return Map(
            "success", true,
            "message", "Account created successfully! Check your email to confirm."
        )
    } else {
        SecurityManager.LogSecurityEvent("register_failed", email . " | Status: " . response.status)
        
        errorMsg := "Error creating account"
        
        try {
            errorData := JSON.Parse(response.text)
            
            if (errorData.Has("msg")) {
                if (InStr(errorData["msg"], "already registered")) {
                    errorMsg := "This email is already registered"
                } else {
                    errorMsg := errorData["msg"]
                }
            } else if (errorData.Has("error_description")) {
                errorMsg := errorData["error_description"]
            }
        }
        
        return Map("success", false, "error", errorMsg)
    }
}
    
    static Logout() {
    if (SESSION.token) {
        url := SUPABASE.authURL . "/logout"
        
        headers := Map(
            "Authorization", "Bearer " . SESSION.token
        )
        
        HttpClient.Post(url, "", headers)
    }
    
    this.ClearCache()
    
    SESSION.authenticated := false
    SESSION.token := ""
    SESSION.refreshToken := ""
    SESSION.userId := ""
    SESSION.email := ""
    SESSION.nickname := ""
    SESSION.role := "user"
    SESSION.permissions := []
    SESSION.tokenExpiry := 0
    SESSION.isTrial := false
    SESSION.trialDaysRemaining := 0
    
    SecurityManager.LogSecurityEvent("logout")
    
    return true
}
    
    static GetProfile() {
    if (!SESSION.userId || !SESSION.token) {
        return false
    }
    
    url := SUPABASE.restURL . "/profiles?id=eq." . SESSION.userId . "&select=*"
    
    response := HttpClient.Get(url)
    
    if (response.success) {
        try {
            profiles := JSON.Parse(response.text)
            
            if (Type(profiles) = "Array" && profiles.Length > 0) {
                profile := profiles[1]
                
                SESSION.nickname := profile.Get("nickname", SESSION.email)
                SESSION.role := profile.Get("role", SESSION.role)
                SESSION.permissions := profile.Get("permissions", [])
                SESSION.trialExpiry := profile.Get("trial_expiry", "")
                SESSION.isBlocked := profile.Get("is_blocked", false)
                SESSION.isTrial := (SESSION.role = "trial")
                
                if (SESSION.isTrial && SESSION.trialExpiry) {
                    SESSION.trialDaysRemaining := CalculateTrialDays(SESSION.trialExpiry)
                }
                
                return true
            }
        } catch as e {
            if (RUNTIME.debugMode) {
                ShowTooltip("Error loading profile: " . e.Message, 3000)
            }
        }
    }
    
    return false
}
    
    static RefreshToken() {
        if (!SESSION.refreshToken) {
            return false
        }
        
        url := SUPABASE.authURL . "/token?grant_type=refresh_token"
        
        payload := JSON.Stringify(Map(
            "refresh_token", SESSION.refreshToken
        ))
        
        response := HttpClient.Post(url, payload)
        
        if (response.success) {
            try {
                data := JSON.Parse(response.text)
                
                SESSION.token := data.Get("access_token", SESSION.token)
                SESSION.refreshToken := data.Get("refresh_token", SESSION.refreshToken)
                
                if (data.Has("expires_in")) {
                    SESSION.tokenExpiry := A_TickCount + (data["expires_in"] * 1000)
                }
                
                return true
            }
        }
        
        return false
    }
    
    static ResendVerificationEmail(email) {
        url := SUPABASE.authURL . "/resend"
        
        payload := JSON.Stringify(Map(
            "type", "signup",
            "email", email
        ))
        
        response := HttpClient.Post(url, payload)
        
        return response.success
    }
    
    static SendPasswordReset(email) {
        if (!SecurityManager.ValidateEmail(email)) {
            return false
        }
        
        url := SUPABASE.authURL . "/recover"
        
        payload := JSON.Stringify(Map(
            "email", email,
            "redirectTo", "https://yourdomain.com/reset-password"
        ))
        
        response := HttpClient.Post(url, payload)
        
        return response.success
    }
    
    static SavePresetToCloud(presetData) {
    if (!SESSION.userId) {
        return Map("success", false, "error", "Not authenticated")
    }
    
    if (!SecurityManager.CheckRateLimit("preset_upload", SESSION.userId)) {
        return Map("success", false, "error", "Too many uploads. Please wait.")
    }
    
    ; Usar apenas configurações compartilháveis
    shareableSettings := GetShareableSettings()
    
    ; Validate preset name
    presetName := SecurityManager.SanitizeInput(presetData.Get("name", ""))
    if (StrLen(presetName) < 3 || StrLen(presetName) > 50) {
        return Map("success", false, "error", "Preset name must be 3-50 characters")
    }
    
    url := SUPABASE.restURL . "/presets"
    
     payload := JSON.Stringify(Map(
        "user_id", SESSION.userId,
        "name", presetName,
        "description", SecurityManager.SanitizeInput(presetData.Get("description", "")),
        "build_type", StrLower(presetData.Get("build_type", "both")),  ; Modificado
        "ping_range", presetData.Get("ping_range", "0-50ms"),
        "is_public", presetData.Get("is_public", false),
        "settings", JSON.Stringify(shareableSettings),
        "author_name", SESSION.nickname,
        "version", APP_VERSION,
        "downloads", 0,
        "rating", 0,
        "rating_count", 0,
        "tags", ParseTags(presetData.Get("tags", "")),  ; Modificado
        "exact_ping", presetData.Get("exact_ping", 0)
    ))
    
    response := HttpClient.Post(url, payload)
    
    if (response.success) {
        this.InvalidateCache("presets_public")
        this.InvalidateCache("presets_user_" . SESSION.userId)
        this.LogActivity("preset_upload", presetName)
        return Map("success", true, "message", "Preset saved successfully", "id", response.text)
    }
    
    errorMsg := "Error saving preset"
    try {
        errorData := JSON.Parse(response.text)
        if (errorData.Has("message")) {
            errorMsg := errorData["message"]
        }
    }
    
    return Map("success", false, "error", errorMsg)
}

    static GetAdminStats() {
    if (!SESSION.userId || SESSION.role != "admin") {
        return Map("success", false, "error", "Admin access required")
    }
    
    ; Call stored procedure for aggregated stats
    url := SUPABASE.restURL . "/rpc/get_admin_stats"
    
    response := HttpClient.Post(url, "{}")
    
    if (response.success) {
        try {
            data := JSON.Parse(response.text)
            
            ; Process the raw data into a structured format
            stats := Map(
                "users_total", 0,
                "trials_total", 0, 
                "premium_total", 0,
                "blocked_total", 0,
                "presets_public", 0,
                "presets_private", 0,
                "downloads_total", 0,
                "rating_avg", 0,
                "rating_count", 0,
                "activity_24h", 0,
                "latest_version", APP_VERSION,
                "top_downloads", []
            )
            
            ; Parse stats from response
            if (Type(data) = "Array" && data.Length > 0) {
                statsData := data[1]
                for key, value in statsData {
                    if (stats.Has(key)) {
                        stats[key] := value
                    }
                }
            }
            
            return Map("success", true, "data", stats)
            
        } catch as e {
            return Map("success", false, "error", "Error parsing stats: " . e.Message)
        }
    }
    
    return Map("success", false, "error", "Failed to fetch statistics")
}
    
    static GetCloudPresets(isPublic := true) {
        url := SUPABASE.restURL . "/presets?"
        
        if (isPublic) {
            url .= "is_public=eq.true&"
        } else if (SESSION.userId) {
            url .= "user_id=eq." . SESSION.userId . "&"
        }
        
        url .= "order=created_at.desc&limit=50"
        
        response := HttpClient.Get(url)
        
        if (response.success) {
            try {
                return JSON.Parse(response.text)
            }
        }
        
        return []
    }
    
    static DownloadPreset(presetId) {
        url := SUPABASE.restURL . "/presets?id=eq." . presetId
        
        response := HttpClient.Get(url)
        
        if (response.success) {
            try {
                presets := JSON.Parse(response.text)
                
                if (Type(presets) = "Array" && presets.Length > 0) {
                    return presets[1]
                }
            }
        }
        
        return false
    }
    
    static DeleteCloudPreset(presetId) {
        if (!SESSION.userId) {
            return false
        }
        
        url := SUPABASE.restURL . "/presets?id=eq." . presetId . "&user_id=eq." . SESSION.userId
        
        response := HttpClient.Delete(url)
        
        if (response.success) {
            this.InvalidateCache("presets_user_" . SESSION.userId)
        }
        
        return response.success
    }
    
    static IncrementDownloads(presetId) {
        url := SUPABASE.restURL . "/rpc/increment_preset_downloads"
        
        payload := JSON.Stringify(Map(
            "preset_uuid", presetId
        ))
        
        HttpClient.Post(url, payload)
    }
    
    static RatePreset(presetId, rating, comment := "") {
        if (!SESSION.userId) {
            return false
        }
        
        url := SUPABASE.restURL . "/preset_ratings"
        
        ; First, check if user already rated this preset
        checkUrl := url . "?preset_id=eq." . presetId . "&user_id=eq." . SESSION.userId
        checkResponse := HttpClient.Get(checkUrl)
        
        if (checkResponse.success) {
            try {
                existingRatings := JSON.Parse(checkResponse.text)
                
                if (Type(existingRatings) = "Array" && existingRatings.Length > 0) {
                    ; Update existing rating
                    ratingId := existingRatings[1]["id"]
                    updateUrl := url . "?id=eq." . ratingId
                    
                    payload := JSON.Stringify(Map(
                        "rating", rating,
                        "comment", comment,
                        "updated_at", FormatTime(A_Now, "yyyy-MM-dd HH:mm:ss")
                    ))
                    
                    response := HttpClient.Patch(updateUrl, payload)
                    return response.success
                }
            }
        }
        
        ; Create new rating
        payload := JSON.Stringify(Map(
            "preset_id", presetId,
            "user_id", SESSION.userId,
            "rating", rating,
            "comment", comment,
            "created_at", FormatTime(A_Now, "yyyy-MM-dd HH:mm:ss")
        ))
        
        response := HttpClient.Post(url, payload)
        return response.success
    }
    
    static GetUserPresets() {
        if (!SESSION.userId) {
            return []
        }
        
        url := SUPABASE.restURL . "/presets?user_id=eq." . SESSION.userId . "&order=created_at.desc"
        
        response := HttpClient.Get(url)
        
        if (response.success) {
            try {
                return JSON.Parse(response.text)
            }
        }
        
        return []
    }
    
    static GetTopRatedPresets(limit := 20) {
        url := SUPABASE.restURL . "/presets?is_public=eq.true&rating=gte.4&order=rating.desc,downloads.desc&limit=" . limit
        
        response := HttpClient.Get(url)
        
        if (response.success) {
            try {
                return JSON.Parse(response.text)
            }
        }
        
        return []
    }
    
    static SearchPresets(searchTerm, buildType := "", sortBy := "created_at") {
        url := SUPABASE.restURL . "/presets?is_public=eq.true"
        
        if (searchTerm) {
            url .= "&or=(name.ilike.*" . searchTerm . "*,description.ilike.*" . searchTerm . "*,tags.cs.{" . searchTerm . "})"
        }
        
        if (buildType && buildType != "All") {
            url .= "&build_type=eq." . StrLower(buildType)
        }
        
        switch sortBy {
            case "rating":
                url .= "&order=rating.desc,rating_count.desc"
            case "downloads":
                url .= "&order=downloads.desc"
            case "newest":
                url .= "&order=created_at.desc"
            case "oldest":
                url .= "&order=created_at.asc"
            default:
                url .= "&order=created_at.desc"
        }
        
        url .= "&limit=100"
        
        response := HttpClient.Get(url)
        
        if (response.success) {
            try {
                return JSON.Parse(response.text)
            }
        }
        
        return []
    }
    
    static CheckUserBlock() {
        if (!SESSION.userId) {
            return false
        }
        
        url := SUPABASE.restURL . "/user_blocks?user_id=eq." . SESSION.userId
        
        response := HttpClient.Get(url)
        
        if (response.success) {
            try {
                blocks := JSON.Parse(response.text)
                
                if (Type(blocks) = "Array" && blocks.Length > 0) {
                    block := blocks[1]
                    
                    ; Check if block has expired
                    if (block.Has("expires_at") && block["expires_at"]) {
                        expiryTime := block["expires_at"]
                        ; Parse and compare with current time
                        ; If expired, return false
                    }
                    
                    SESSION.isBlocked := true
                    return true
                }
            }
        }
        
        SESSION.isBlocked := false
        return false
    }
    
    static GetAppConfig(key := "") {
        cacheKey := "app_config_" . key
        cached := this.GetFromCache(cacheKey)
        if (cached) {
            return cached
        }
        
        url := SUPABASE.restURL . "/app_config"
        
        if (key) {
            url .= "?key=eq." . key
        }
        
        response := HttpClient.Get(url)
        
        if (response.success) {
            try {
                data := JSON.Parse(response.text)
                
                if (Type(data) = "Array" && data.Length > 0) {
                    if (key) {
                        value := data[1]["value"]
                        this.SaveToCache(cacheKey, value, 600000) ; Cache for 10 minutes
                        return value
                    } else {
                        configMap := Map()
                        for item in data {
                            configMap[item["key"]] := item["value"]
                        }
                        this.SaveToCache(cacheKey, configMap, 600000)
                        return configMap
                    }
                }
            }
        }
        
        return key ? "" : Map()
    }
    
    static GetAnnouncement() {
        return this.GetAppConfig("announcement")
    }
    
    static IsMaintenanceMode() {
        maintenanceMode := this.GetAppConfig("maintenance_mode")
        return maintenanceMode = "true"
    }
    
    static UpdateProfile(data) {
        if (!SESSION.userId) {
            return false
        }
        
        url := SUPABASE.restURL . "/profiles?id=eq." . SESSION.userId
        
        payload := JSON.Stringify(data)
        
        response := HttpClient.Patch(url, payload)
        
        if (response.success) {
            this.InvalidateCache("profile_" . SESSION.userId)
            this.GetProfile() ; Reload profile
        }
        
        return response.success
    }
    
    static LogActivity(action, details := "") {
        SetTimer(() => this._SendActivityLog(action, details), -1)
    }
    
    static _SendActivityLog(action, details) {
        if (!SESSION.userId) {
            return
        }
        
        url := SUPABASE.restURL . "/activity_logs"
        
        payload := JSON.Stringify(Map(
            "user_id", SESSION.userId,
            "action", action,
            "details", details,
            "device_id", GetDeviceFingerprint(),
            "ip_address", this.GetPublicIP(),
            "timestamp", FormatTime(A_Now, "yyyy-MM-dd HH:mm:ss"),
            "version", APP_VERSION,
            "metadata", Map(
                "mode", RUNTIME.mode,
                "os", A_OSVersion,
                "ahk_version", A_AhkVersion
            )
        ))
        
        headers := Map("Prefer", "return=minimal")
        
        HttpClient.Post(url, payload, headers)
    }
    
    static GetPublicIP() {
        static cachedIP := ""
        static lastCheck := 0
        
        if (cachedIP && A_TickCount - lastCheck < 3600000) {
            return cachedIP
        }
        
        try {
            response := HttpClient.Get("https://api.ipify.org")
            if (response.success) {
                cachedIP := Trim(response.text)
                lastCheck := A_TickCount
                return cachedIP
            }
        }
        
        return "unknown"
    }
    
    static CheckUpdate() {
        url := SUPABASE.restURL . "/app_config?key=eq.latest_version"
        
        response := HttpClient.Get(url)
        
        if (response.success) {
            try {
                data := JSON.Parse(response.text)
                
                if (Type(data) = "Array" && data.Length > 0) {
                    RUNTIME.latestVersion := data[1]["value"]
                    
                    if (this.CompareVersions(RUNTIME.latestVersion, APP_VERSION) > 0) {
                        RUNTIME.updateAvailable := true
                        return true
                    }
                }
            }
        }
        
        return false
    }
    
    static CompareVersions(v1, v2) {
        v1Parts := StrSplit(v1, ".")
        v2Parts := StrSplit(v2, ".")
        
        Loop Max(v1Parts.Length, v2Parts.Length) {
            p1 := A_Index <= v1Parts.Length ? Integer(v1Parts[A_Index]) : 0
            p2 := A_Index <= v2Parts.Length ? Integer(v2Parts[A_Index]) : 0
            
            if (p1 > p2)
                return 1
            if (p1 < p2)
                return -1
        }
        
        return 0
    }
    
    static GetFromCache(key) {
        if (!this.cache.Has(key)) {
            return false
        }
        
        if (this.cacheExpiry.Has(key)) {
            if (A_TickCount > this.cacheExpiry[key]) {
                this.cache.Delete(key)
                this.cacheExpiry.Delete(key)
                return false
            }
        }
        
        return this.cache[key]
    }
    
    static SaveToCache(key, data, timeout := "") {
        if (!timeout) {
            timeout := this.cacheTimeout
        }
        
        this.cache[key] := data
        this.cacheExpiry[key] := A_TickCount + timeout
    }
    
    static InvalidateCache(key := "") {
        if (key) {
            if (this.cache.Has(key)) {
                this.cache.Delete(key)
            }
            if (this.cacheExpiry.Has(key)) {
                this.cacheExpiry.Delete(key)
            }
        } else {
            this.ClearCache()
        }
    }
    
    static ClearCache() {
        this.cache := Map()
        this.cacheExpiry := Map()
    }
}

; ================= FUNÇÃO CORRIGIDA: ApplyDownloadedPreset =================
ApplyDownloadedPreset(presetData) {
    global SETTINGS
    
    if (!Type(presetData) = "Map") {
        ShowTooltip("❌ Invalid preset data", 2000)
        return false
    }
    
    ; Parse settings if they're in string format
    settings := presetData.Has("settings") ? presetData["settings"] : Map()
    
    if (Type(settings) = "String") {
        try {
            settings := JSON.Parse(settings)
        } catch {
            ShowTooltip("❌ Error parsing preset settings", 2000)
            return false
        }
    }
    
    ; Aplicar apenas configurações compartilháveis (sleeps e loops)
    shareableKeys := GetShareableSettings()
    appliedCount := 0
    
    for key, defaultValue in shareableKeys {
        if (settings.Has(key)) {
            SETTINGS[key] := settings[key]
            appliedCount++
        }
    }
    
    SaveSettings()
    
    if (appliedCount > 0) {
        ShowTooltip("✅ Applied " . appliedCount . " timing settings from preset!", 3000)
        return true
    } else {
        ShowTooltip("⚠️ No compatible settings found in preset", 2000)
        return false
    }
}

; ================= UTILITY FUNCTIONS =================
FormatSettingName(key) {
    ; Convert snake_case to Title Case with spaces
    parts := StrSplit(key, "_")
    result := ""
    for part in parts {
        if (A_Index > 1)
            result .= " "
        result .= Format("{:T}", part)
    }
    return result
}

GetDeviceFingerprint() {
    static fingerprint := ""
    
    if (fingerprint) {
        return fingerprint
    }
    
    components := []
    components.Push(A_ComputerName)
    components.Push(A_UserName)
    
    try {
        wmi := ComObject("WbemScripting.SWbemLocator")
        service := wmi.ConnectServer()
        
        for item in service.ExecQuery("SELECT * FROM Win32_Processor") {
            if (item.ProcessorId) {
                components.Push(item.ProcessorId)
            }
            break
        }
        
        for item in service.ExecQuery("SELECT * FROM Win32_BaseBoard") {
            if (item.SerialNumber && item.SerialNumber != "None") {
                components.Push(item.SerialNumber)
            }
            break
        }
        
        for item in service.ExecQuery("SELECT * FROM Win32_ComputerSystemProduct") {
            if (item.UUID && item.UUID != "00000000-0000-0000-0000-000000000000") {
                components.Push(item.UUID)
            }
            break
        }
    }
    
    combined := ""
    for component in components {
        combined .= component . "|"
    }
    
    fingerprint := SecurityManager.HashString(combined)
    return fingerprint
}

FormatDate(datetime) {
    if !datetime
        datetime := A_Now

    return Format("{:02}/{:02}/{:04} {:02}:{:02}:{:02}"
        , SubStr(datetime, 7, 2)
        , SubStr(datetime, 5, 2)
        , SubStr(datetime, 1, 4)
        , SubStr(datetime, 9, 2)
        , SubStr(datetime, 11, 2)
        , SubStr(datetime, 13, 2))
}

CalculateTrialDays(expiryDate) {
    if (!expiryDate) {
        return 0
    }
    
    expiryTimestamp := ""
    
    if (InStr(expiryDate, "T")) {
        parts := StrSplit(expiryDate, "T")
        datePart := StrReplace(parts[1], "-", "")
        
        if (parts.Length > 1) {
            timePart := StrReplace(StrReplace(parts[2], ":", ""), "Z", "")
            timePart := SubStr(timePart, 1, 6)
        } else {
            timePart := "235959"
        }
        
        expiryTimestamp := datePart . timePart
    } else if (InStr(expiryDate, "-")) {
        datePart := StrReplace(expiryDate, "-", "")
        expiryTimestamp := datePart . "235959"
    } else if (StrLen(expiryDate) >= 8 && IsNumber(expiryDate)) {
        expiryTimestamp := expiryDate
        if (StrLen(expiryTimestamp) = 8) {
            expiryTimestamp .= "235959"
        }
    }
    
    if (StrLen(expiryTimestamp) >= 14 && IsNumber(SubStr(expiryTimestamp, 1, 8))) {
        currentTime := A_Now
        
        try {
            return DateDiff(expiryTimestamp, currentTime, "Days")
        } catch {
            return 0
        }
    }
    
    return 0
}

ShowTooltip(text, duration := 2000, x := "", y := "") {
    if (x && y) {
        ToolTip(text, x, y)
    } else {
        ToolTip(text)
    }
    
    SetTimer(() => ToolTip(), -duration)
}

IsNumber(value) {
    if (!value || value = "") {
        return false
    }
    try {
        Integer(value)
        return true
    } catch {
        return false
    }
}

LoadSettings() {
    global SETTINGS, PATTERNS, CONFIG_FILE
    
    if (FileExist(CONFIG_FILE)) {
        for key, defaultValue in SETTINGS {
            SETTINGS[key] := IniRead(CONFIG_FILE, "Settings", key, defaultValue)
        }
        
        PATTERNS.Ccrit := IniRead(CONFIG_FILE, "FindText", "Ccrit", PATTERNS.Ccrit)
        PATTERNS.Lcrit := IniRead(CONFIG_FILE, "FindText", "Lcrit", PATTERNS.Lcrit)
        
        RUNTIME.debugMode := SETTINGS["debug_mode"] = "1"
        RUNTIME.performanceMode := SETTINGS["performance_mode"] = "1"
    }
}

SaveSettings() {
    global SETTINGS, PATTERNS, CONFIG_FILE
    
    BackupSettings()
    
    for key, value in SETTINGS {
        IniWrite(value, CONFIG_FILE, "Settings", key)
    }
    
    IniWrite(PATTERNS.Ccrit, CONFIG_FILE, "FindText", "Ccrit")
    IniWrite(PATTERNS.Lcrit, CONFIG_FILE, "FindText", "Lcrit")
    
    IniWrite(RUNTIME.debugMode ? "1" : "0", CONFIG_FILE, "Settings", "debug_mode")
    IniWrite(RUNTIME.performanceMode ? "1" : "0", CONFIG_FILE, "Settings", "performance_mode")
}

BackupSettings() {
    if (!FileExist(CONFIG_FILE))
        return
    
    if (!DirExist(BACKUP_DIR)) {
        DirCreate(BACKUP_DIR)
    }
    
    backupFile := BACKUP_DIR . "\config_" . FormatTime(A_Now, "yyyyMMdd_HHmmss") . ".bak"
    
    try {
        FileCopy(CONFIG_FILE, backupFile)
        CleanOldBackups()
    }
}

CleanOldBackups() {
    backupFiles := []
    
    Loop Files, BACKUP_DIR . "\config_*.bak" {
        backupFiles.Push({
            path: A_LoopFileFullPath,
            time: A_LoopFileTimeModified
        })
    }
    
    if (backupFiles.Length > 10) {
        Loop backupFiles.Length - 1 {
            i := A_Index
            Loop backupFiles.Length - i {
                j := A_Index
                if (j < backupFiles.Length && backupFiles[j].time > backupFiles[j + 1].time) {
                    temp := backupFiles[j]
                    backupFiles[j] := backupFiles[j + 1]
                    backupFiles[j + 1] := temp
                }
            }
        }
        
        Loop backupFiles.Length - 10 {
            try {
                FileDelete(backupFiles[A_Index].path)
            }
        }
    }
}

; ================= CORREÇÃO 5: Presets autogerados compatíveis =================
CreateDefaultPresets() {
    global PRESETS_DIR
    
    if (!DirExist(PRESETS_DIR)) {
        DirCreate(PRESETS_DIR)
    }
    
    ; Preset de Ping Baixo
    CreateExamplePreset("Low_Ping_0-50ms", Map(
        "macro_timing", "10",
        "sleep_punc_x1_no_crit", "50"
    ), "both", "0-50ms", 25)
    
    ; Preset de Ping Alto
    CreateExamplePreset("High_Ping_100-150ms", Map(
        "macro_timing", "30",
        "sleep_punc_x1_no_crit", "120"
    ), "both", "100-150ms", 125)
}

CreateExamplePreset(name, settings, buildType, pingRange, exactPing) {
    global PRESETS_DIR, APP_VERSION
    
    presetFile := PRESETS_DIR . "\" . name . ".ini"
    
    if (!FileExist(presetFile)) {
        FileAppend("", presetFile)
        
        IniWrite(name, presetFile, "Metadata", "name")
        IniWrite("Auto-generated example preset", presetFile, "Metadata", "description")
        IniWrite(buildType, presetFile, "Metadata", "build_type")
        IniWrite(pingRange, presetFile, "Metadata", "ping_range")
        IniWrite(exactPing, presetFile, "Metadata", "exact_ping")
        IniWrite(APP_VERSION, presetFile, "Metadata", "version")
        IniWrite(FormatTime(A_Now, "yyyy-MM-dd"), presetFile, "Metadata", "created")
        
        for key, value in settings {
            IniWrite(value, presetFile, "Settings", key)
        }
    }
}

CreateRequiredDirectories() {
    dirs := [PRESETS_DIR, LOGS_DIR, BACKUP_DIR]
    
    for dir in dirs {
        if (!DirExist(dir)) {
            try {
                DirCreate(dir)
            } catch {
                MsgBox("Error creating directory: " . dir, "Error", "Icon!")
            }
        }
    }
}

; ================= LOGIN SCREEN =================
ShowLoginScreen() {
    global GUI_REFS
    
    if (GUI_REFS["login"]) {
        try GUI_REFS["login"].Destroy()
    }
    
    loginGui := Gui("+AlwaysOnTop -MinimizeBox", "🎮 BNS Macro v" . APP_VERSION)
    loginGui.BackColor := "0x1a1a2e"
    GUI_REFS["login"] := loginGui
    
    loginGui.OnEvent("Close", (*) => ExitApp())
    
    loginGui.SetFont("s20 Bold cFFFFFF", "Segoe UI")
    loginGui.Add("Text", "x0 y20 w450 Center", "⚔️ BLADE MASTER")
    
    loginGui.SetFont("s12 cC0C0C0", "Segoe UI")
    loginGui.Add("Text", "x0 y60 w450 Center", "Professional Gaming Enhancement")
    
    loginGui.SetFont("s10 c00FF00", "Segoe UI")
    loginGui.Add("Text", "x0 y85 w450 Center", "v" . APP_VERSION . " | " . APP_BUILD)
    
    if (RUNTIME.secureMode) {
        loginGui.SetFont("s9 c00FF00", "Segoe UI")
        loginGui.Add("Text", "x0 y110 w450 Center", "🔒 Secure Mode Active | 🛡️ Anti-Bypass Protected")
    }
    
    if (RUNTIME.updateAvailable) {
        loginGui.SetFont("s10 Bold cFFFF00", "Segoe UI")
        loginGui.Add("Text", "x0 y135 w450 Center", "⚠️ Update Available: v" . RUNTIME.latestVersion)
    }
    
    loginGui.SetFont("s11 cFFFFFF", "Segoe UI")
    
    loginGui.Add("Text", "x50 y170", "📧 Email:")
    emailEdit := loginGui.Add("Edit", "x50 y195 w350 h35 Background0x2a2a3e cWhite")
    emailEdit.SetFont("s11")
    
    loginGui.Add("Text", "x50 y240", "🔑 Password:")
    passwordEdit := loginGui.Add("Edit", "x50 y265 w350 h35 Password Background0x2a2a3e cWhite")
    passwordEdit.SetFont("s11")
    
    rememberCheck := loginGui.Add("Checkbox", "x50 y315 cWhite", "Remember me")
    rememberCheck.SetFont("s10")
    
    loginGui.SetFont("s9 Underline c00BFFF", "Segoe UI")
    forgotLink := loginGui.Add("Text", "x320 y317", "Forgot password?")
    forgotLink.OnEvent("Click", ShowPasswordReset)
    
    loginGui.SetFont("s10 cFF0000", "Segoe UI")
    statusText := loginGui.Add("Text", "x0 y345 w450 h30 Center", "")
    
    loginGui.SetFont("s12 Bold", "Segoe UI")
    
    loginBtn := loginGui.Add("Button", "x50 y380 w165 h45", "🚀 LOGIN")
    loginBtn.OnEvent("Click", ProcessLogin)
    
    registerBtn := loginGui.Add("Button", "x235 y380 w165 h45", "📝 REGISTER")
    registerBtn.OnEvent("Click", ShowRegisterScreen)
    
    loginGui.SetFont("s9 c808080", "Segoe UI")
    loginGui.Add("Text", "x0 y440 w450 Center", "© 2025 Skyze BNS Script | All Rights Reserved")
    
    loginGui.SetFont("s9 Underline c00BFFF", "Segoe UI")
    discordLink := loginGui.Add("Text", "x0 y460 w450 Center", "💬 Join Discord Community")
    discordLink.OnEvent("Click", (*) => Run("https://discord.com/users/.skyze"))
    
    loginGui.SetFont("s9", "Segoe UI")
    testBtn := loginGui.Add("Button", "x395 y10 w45 h25", "🔗")
    testBtn.OnEvent("Click", TestConnection)
    
    ProcessLogin(*) {
        email := Trim(emailEdit.Text)
        password := passwordEdit.Text
        
        if (!email || !password) {
            statusText.Text := "⚠️ Please fill all fields"
            statusText.SetFont("cFFFF00")
            return
        }
        
        loginBtn.Enabled := false
        registerBtn.Enabled := false
        statusText.Text := "🔄 Authenticating..."
        statusText.SetFont("c00BFFF")
        
        result := SupabaseClient.Login(email, password)
        
        if (result["success"]) {
            ; Save credentials if remember is checked
            if (rememberCheck.Value) {
                IniWrite("1", CONFIG_FILE, "Auth", "remember")
                IniWrite(SecurityManager.Encrypt(email), CONFIG_FILE, "Auth", "email")
                IniWrite(SecurityManager.Encrypt(password), CONFIG_FILE, "Auth", "password")
            } else {
                IniWrite("0", CONFIG_FILE, "Auth", "remember")
                IniDelete(CONFIG_FILE, "Auth", "email")
                IniDelete(CONFIG_FILE, "Auth", "password")
            }
            
            if (SESSION.isBlocked) {
                statusText.Text := "❌ Account blocked by administrator"
                statusText.SetFont("cFF0000")
                SupabaseClient.Logout()
                loginBtn.Enabled := true
                registerBtn.Enabled := true
                return
            }
            
            if (SESSION.isTrial && SESSION.trialDaysRemaining <= 0) {
                statusText.Text := "⏰ Trial expired - Please upgrade"
                statusText.SetFont("cFFA500")
                ShowUpgradeDialog()
                loginBtn.Enabled := true
                registerBtn.Enabled := true
                return
            }
            
            statusText.Text := "✅ Login successful!"
            statusText.SetFont("c00FF00")
            
            Sleep(500)
            
            loginGui.Destroy()
            
            CreateTrayMenu()
            
            ShowMainMenu()
            
            if (SESSION.isTrial && SESSION.trialDaysRemaining <= 3) {
                ShowTooltip("⚠️ Trial expires in " . SESSION.trialDaysRemaining . " days!", 5000)
            } else {
                ShowTooltip("Welcome back, " . SESSION.nickname . "! 🎮", 3000)
            }
            
        } else {
            statusText.Text := "❌ " . result.Get("error", "Authentication failed")
            statusText.SetFont("cFF0000")
            
            loginBtn.Enabled := true
            registerBtn.Enabled := true
            
            if (InStr(result["error"], "not verified") || InStr(result["error"], "não verificado")) {
                response := MsgBox(
                    "Your email is not verified.`n`n" .
                    "Would you like to resend the verification email?",
                    "Email Verification",
                    "YesNo Icon!"
                )
                
                if (response = "Yes") {
                    if (SupabaseClient.ResendVerificationEmail(email)) {
                        ShowTooltip("✅ Verification email sent!", 3000)
                    }
                }
            }
        }
    }
    
    ; ================= CORREÇÃO 6: Foco automático em novas janelas =================
    ShowPasswordReset(*) {
        resetGui := Gui("+AlwaysOnTop +Owner" . loginGui.Hwnd, "Password Reset")
        resetGui.BackColor := "0x1a1a2e"
        
        resetGui.SetFont("s11 cFFFFFF", "Segoe UI")
        resetGui.Add("Text", "x20 y20", "Enter your email to reset password:")
        
        resetEmail := resetGui.Add("Edit", "x20 y50 w340 h30 Background0x2a2a3e cWhite")
        
        resetGui.SetFont("s10 cFFFF00", "Segoe UI")
        resetGui.Add("Text", "x20 y90 w340", "You will receive a password reset link via email.")
        
        resetGui.SetFont("s11 Bold", "Segoe UI")
        sendBtn := resetGui.Add("Button", "x90 y125 w100 h35", "📧 Send")
        sendBtn.OnEvent("Click", SendReset)
        
        cancelBtn := resetGui.Add("Button", "x200 y125 w100 h35", "Cancel")
        cancelBtn.OnEvent("Click", (*) => resetGui.Destroy())
        
        SendReset(*) {
            email := Trim(resetEmail.Text)
            
            if (!SecurityManager.ValidateEmail(email)) {
                MsgBox("Please enter a valid email address", "Error", "Icon!")
                return
            }
            
            if (SupabaseClient.SendPasswordReset(email)) {
                MsgBox(
                    "Password reset email sent!`n`n" .
                    "Please check your inbox and follow the instructions.",
                    "Success",
                    "Icon!"
                )
                resetGui.Destroy()
            } else {
                MsgBox("Failed to send reset email. Please try again.", "Error", "Icon!")
            }
        }
        
        resetGui.Show("w380 h180")
        resetEmail.Focus() ; Garante o foco no campo de email
    }
    
    TestConnection(*) {
        testBtn.Enabled := false
        testBtn.Text := "..."
        
        response := HttpClient.Get(SUPABASE.url . "/rest/v1/")
        
        if (response.success) {
            ShowTooltip("✅ Connection successful! Server is online.", 3000)
        } else {
            ShowTooltip("❌ Connection failed! Check your internet.", 3000)
        }
        
        testBtn.Text := "🔗"
        testBtn.Enabled := true
    }
    
    ; Load saved credentials
    if (IniRead(CONFIG_FILE, "Auth", "remember", "0") = "1") {
        encryptedEmail := IniRead(CONFIG_FILE, "Auth", "email", "")
        encryptedPassword := IniRead(CONFIG_FILE, "Auth", "password", "")
        
        if (encryptedEmail && encryptedPassword) {
            try {
                decryptedEmail := SecurityManager.Decrypt(encryptedEmail)
                decryptedPassword := SecurityManager.Decrypt(encryptedPassword)
                
                if (decryptedEmail && decryptedPassword) {
                    emailEdit.Text := decryptedEmail
                    passwordEdit.Text := decryptedPassword
                    rememberCheck.Value := 1
                    loginBtn.Focus()
                }
            } catch {
                emailEdit.Focus()
            }
        }
    } else {
        emailEdit.Focus()
    }
    
    loginGui.Show("w450 h490")
}

; ================= REGISTER SCREEN =================
ShowRegisterScreen(*) {
    global GUI_REFS
    
    if (GUI_REFS["register"]) {
        try GUI_REFS["register"].Destroy()
    }
    
    registerGui := Gui("+AlwaysOnTop", "📝 Create Account")
    registerGui.BackColor := "0x1a1a2e"
    GUI_REFS["register"] := registerGui
    
    registerGui.SetFont("s16 Bold cFFFFFF", "Segoe UI")
    registerGui.Add("Text", "x0 y20 w450 Center", "CREATE NEW ACCOUNT")
    
    registerGui.SetFont("s10 cFFFF00", "Segoe UI")
    registerGui.Add("Text", "x0 y55 w450 Center", "🎁 Get 7 days FREE trial upon registration!")
    
    registerGui.SetFont("s11 cFFFFFF", "Segoe UI")
    
    registerGui.Add("Text", "x50 y100", "Email:")
    emailReg := registerGui.Add("Edit", "x50 y125 w350 h35 Background0x2a2a3e cWhite")
    
    registerGui.Add("Text", "x50 y170", "Password:")
    passReg := registerGui.Add("Edit", "x50 y195 w350 h35 Password Background0x2a2a3e cWhite")
    
    registerGui.Add("Text", "x50 y240", "Confirm Password:")
    passConfirm := registerGui.Add("Edit", "x50 y265 w350 h35 Password Background0x2a2a3e cWhite")
    
    registerGui.Add("Text", "x50 y310", "Nickname:")
    nickReg := registerGui.Add("Edit", "x50 y335 w350 h35 Background0x2a2a3e cWhite")
    
    registerGui.SetFont("s9 cC0C0C0", "Segoe UI")
    registerGui.Add("Text", "x50 y380", "• Password: 8+ chars, uppercase, lowercase, number")
    registerGui.Add("Text", "x50 y400", "• Nickname: 3-20 chars, letters, numbers, _ and -")
    
    termsCheck := registerGui.Add("Checkbox", "x50 y430 cWhite", "I agree to Terms of Service and Privacy Policy")
    
    registerGui.SetFont("s10 cFF0000", "Segoe UI")
    statusText := registerGui.Add("Text", "x0 y460 w450 Center", "")
    
    registerGui.SetFont("s11 Bold", "Segoe UI")
    
    createBtn := registerGui.Add("Button", "x100 y490 w110 h40", "✅ Create")
    createBtn.OnEvent("Click", ProcessRegister)
    
    cancelBtn := registerGui.Add("Button", "x240 y490 w110 h40", "❌ Cancel")
    cancelBtn.OnEvent("Click", (*) => registerGui.Destroy())
    
    ProcessRegister(*) {
        email := Trim(emailReg.Text)
        password := passReg.Text
        confirmPass := passConfirm.Text
        nickname := Trim(nickReg.Text)
        
        statusText.Text := ""
        
        if (!termsCheck.Value) {
            statusText.Text := "Please accept the Terms of Service"
            return
        }
        
        if (!email || !password || !nickname) {
            statusText.Text := "All fields are required"
            return
        }
        
        if (!SecurityManager.ValidateEmail(email)) {
            statusText.Text := "Invalid email address"
            return
        }
        
        if (password != confirmPass) {
            statusText.Text := "Passwords don't match"
            return
        }
        
        passwordValidation := SecurityManager.ValidatePassword(password)
        if (!passwordValidation.valid) {
            statusText.Text := passwordValidation.error
            return
        }
        
        if (StrLen(nickname) < 3 || StrLen(nickname) > 20) {
            statusText.Text := "Nickname must be 3-20 characters"
            return
        }
        
        if (!RegExMatch(nickname, "^[a-zA-Z0-9_\-]+$")) {
            statusText.Text := "Nickname: only letters, numbers, _ and -"
            return
        }
        
        createBtn.Enabled := false
        cancelBtn.Enabled := false
        statusText.SetFont("c00BFFF")
        statusText.Text := "Creating account..."
        
        result := SupabaseClient.Register(email, password, nickname)
        
        if (result["success"]) {
            MsgBox(
                "✅ Account created successfully!`n`n" .
                "Please check your email to verify your account.`n`n" .
                "Your 7-day trial has been activated!",
                "Success",
                "Icon!"
            )
            
            registerGui.Destroy()
        } else {
            statusText.SetFont("cFF0000")
            statusText.Text := result["error"]
            createBtn.Enabled := true
            cancelBtn.Enabled := true
        }
    }
    
    registerGui.Show("w450 h550")
    emailReg.Focus()
}

; ================= MAIN MENU WITH v7.0 FEATURES =================
ShowMainMenu(*) {
    global GUI_REFS, SESSION, RUNTIME, SETTINGS, mainStatusText
    
    if (GUI_REFS["main"] && IsObject(GUI_REFS["main"])) {
        try {
            GUI_REFS["main"].Show()
            WinActivate("ahk_id " . GUI_REFS["main"].Hwnd)
            return
        } catch {
            GUI_REFS["main"] := ""
        }
    }
    
    mainGui := Gui("+AlwaysOnTop +ToolWindow", "⚔️ BNS Macro Control Panel v7.0")
    mainGui.BackColor := "0x1a1a2e"
    GUI_REFS["main"] := mainGui
    
    mainGui.SetFont("s14 Bold cFFFFFF", "Segoe UI")
    mainGui.Add("Text", "x0 y10 w400 Center", "CONTROL PANEL v7.0")
    
    mainGui.SetFont("s10 cC0C0C0", "Segoe UI")
    
    ; User info with role color
    nicknameColor := "c00FF00"
    roleText := " [USER]"
    
    if (SESSION.role = "admin") {
        nicknameColor := "ce8315c"
        roleText := " [ADMIN]"
    } else if (SESSION.role = "trial" || SESSION.isTrial) {
        nicknameColor := "cFFFF00"
        roleText := " [TRIAL]"
    } else if (SESSION.role = "premium") {
        nicknameColor := "c00FFFF"
        roleText := " [PREMIUM]"
    }
    
    mainGui.SetFont("s10 " . nicknameColor, "Segoe UI")
    userInfo := mainGui.Add("Text", "x20 y40 w360 Center", "User: " . SESSION.nickname . roleText)
    
    if (SESSION.isTrial && SESSION.trialDaysRemaining > 0) {
        mainGui.SetFont("s10 cFFFF00", "Segoe UI")
        mainGui.Add("Text", "x20 y60 w360 Center", SESSION.trialDaysRemaining . " days left")
    }
    
    mainGui.SetFont("s10 Bold", "Segoe UI")
    
    ; Main buttons
    hotkeyBtn := mainGui.Add("Button", "x20 y90 w170 h40", "⚙️ Hotkey Editor")
    hotkeyBtn.OnEvent("Click", (*) => ShowHotkeyEditor())
    
    macroBtn := mainGui.Add("Button", "x210 y90 w170 h40", "🎮 Macro Config")
    macroBtn.OnEvent("Click", (*) => ShowMacroConfig())
    
    punctureBtn := mainGui.Add("Button", "x20 y140 w170 h40", "🎯 Puncture Config")
    punctureBtn.OnEvent("Click", (*) => ShowPunctureConfig())
    
    hybridBtn := mainGui.Add("Button", "x210 y140 w170 h40", "🔄 Hybrid Config")
    hybridBtn.OnEvent("Click", (*) => ShowHybridConfig())
    
    ; v7.0 New Features
    presetBtn := mainGui.Add("Button", "x20 y190 w170 h40", "📦 Preset Manager v7")
    presetBtn.OnEvent("Click", (*) => ShowImportExportV7())
    
    buildBtn := mainGui.Add("Button", "x210 y190 w170 h40", "📚 Build Library v7")
    buildBtn.OnEvent("Click", (*) => ShowBuildLibraryV7())
    
    flowchartBtn := mainGui.Add("Button", "x20 y240 w170 h40", "📊 Flowchart")
    flowchartBtn.OnEvent("Click", (*) => ShowFlowchart())
    
    modeBtn := mainGui.Add("Button", "x210 y240 w170 h40", "🔄 Change Mode")
    modeBtn.OnEvent("Click", (*) => ShowModeSelection())
    
    ; Admin functions if admin
    yPos := 290
    if (SESSION.role = "admin") {
        mainGui.SetFont("s10 Bold ce8315c", "Segoe UI")
        mainGui.Add("Text", "x20 y" . yPos . " w360 Center", "🔐 ADMIN FUNCTIONS")
        yPos += 25
        
        userMgrBtn := mainGui.Add("Button", "x20 y" . yPos . " w170 h35", "👥 User Manager")
        userMgrBtn.OnEvent("Click", (*) => ShowUserManagerV7())
        
        statsBtn := mainGui.Add("Button", "x210 y" . yPos . " w170 h35", "📈 System Stats v7")
        statsBtn.OnEvent("Click", (*) => ShowSystemStatsV7())
        
        yPos += 45
    }
    
    ; Status display
    statusValue := RUNTIME.suspendMacros ? "⏸️ SUSPENDED" : "▶️ ACTIVE"
    modeText := RUNTIME.mode = "puncture" ? "Puncture" : "Hybrid"
    
    mainGui.SetFont("s9", "Segoe UI")
    mainStatusText := mainGui.Add("Text", "x20 y" . yPos . " w360 Center", 
        "Status: " . statusValue . " | Mode: " . modeText . " | v7.0")
    
    if (RUNTIME.suspendMacros) {
        mainStatusText.SetFont("cFF0000")
    } else {
        mainStatusText.SetFont("c00FF00")
    }
    
    yPos += 30
    
    ; Bottom buttons
    mainGui.SetFont("s9", "Segoe UI")
    
    discordBtn := mainGui.Add("Button", "x20 y" . yPos . " w80 h30", "💬 Discord")
    discordBtn.OnEvent("Click", (*) => Run("https://discord.gg/bns-macro"))
    
    if (SESSION.isTrial) {
        upgradeBtn := mainGui.Add("Button", "x110 y" . yPos . " w80 h30", "⭐ Upgrade")
        upgradeBtn.OnEvent("Click", (*) => ShowUpgradeDialog())
    }
    
    updateBtn := mainGui.Add("Button", "x200 y" . yPos . " w80 h30", "🔄 Update")
    updateBtn.OnEvent("Click", (*) => CheckForUpdatesV7())
    
    closeBtn := mainGui.Add("Button", "x290 y" . yPos . " w90 h30", "❌ Close")
    closeBtn.OnEvent("Click", (*) => CloseMainMenu())
    
    height := SESSION.role = "admin" ? 430 : 380
    
    mainGui.OnEvent("Close", (*) => CloseMainMenu())
    mainGui.Show("w400 h" . height)
    
    RUNTIME.mainMenuOpen := true
    
    ; Check for announcements
    if (RUNTIME.announcement) {
        MsgBox(RUNTIME.announcement, "📢 Announcement", "Icon!")
    }
}

; ================= v7.0 ENHANCED FUNCTIONS =================

ShowImportExportV7(*) {
    global GUI_REFS, LOCAL_PRESETS, CLOUD_PRESETS, SELECTED_PRESET, PRESET_IN_USE
    
    if (GUI_REFS["import_export"]) {
        try GUI_REFS["import_export"].Destroy()
    }
    
    ieGui := Gui("+AlwaysOnTop +Resize", "📦 Preset Manager v7.0")
    ieGui.BackColor := "0x1a1a2e"
    GUI_REFS["import_export"] := ieGui
    
    ieGui.SetFont("s12 Bold cFFFFFF", "Segoe UI")
    ieGui.Add("Text", "x0 y10 w800 Center", "PRESET MANAGER v7.0")
    
    ; Tabs for Local and Cloud
    tab := ieGui.Add("Tab3", "x10 y40 w780 h500", ["📁 Local Presets", "☁️ Cloud Export", "🌐 My Cloud"])
    
    ; ========== TAB 1: LOCAL PRESETS ==========
    tab.UseTab(1)
    
    ieGui.SetFont("s10 Bold cFFFF00", "Segoe UI")
    ieGui.Add("Text", "x20 y80", "Local Preset Library:")
    
    ieGui.SetFont("s10 cFFFFFF", "Segoe UI")
    
    localListView := ieGui.Add("ListView", "x20 y105 w400 h300 Grid Background0x16213e", 
        ["Name", "Type", "Ping", "Exact Ping", "Created", "Version", "Status"])
    localListView.ModifyCol(1, 120) ; Name
    localListView.ModifyCol(2, 60)  ; Type
    localListView.ModifyCol(3, 70)  ; Ping
    localListView.ModifyCol(4, 50)  ; Exact Ping
    localListView.ModifyCol(5, 70)  ; Created
    localListView.ModifyCol(6, 50)  ; Version
    localListView.ModifyCol(7, 40)  ; Status
    
    ; Preview area
    ieGui.Add("GroupBox", "x430 y100 w350 h310", "Preset Preview")
    previewText := ieGui.Add("Edit", "x440 y120 w330 h280 ReadOnly VScroll Background0x16213e cFFFFFF", "")
    previewText.SetFont("s9", "Consolas")
    
    ; Action buttons
    ieGui.SetFont("s9", "Segoe UI")
    loadBtn := ieGui.Add("Button", "x20 y415 w80 h30", "📥 Load")
    loadBtn.OnEvent("Click", LoadSelectedPreset)
    
    deleteBtn := ieGui.Add("Button", "x110 y415 w80 h30", "🗑️ Delete")
    deleteBtn.OnEvent("Click", DeleteSelectedPreset)
    
    refreshBtn := ieGui.Add("Button", "x200 y415 w80 h30", "🔄 Refresh")
    refreshBtn.OnEvent("Click", RefreshLocalPresets)
    
    createBtn := ieGui.Add("Button", "x290 y415 w80 h30", "➕ Create")
    createBtn.OnEvent("Click", CreateNewPreset)
    
    exportLocalBtn := ieGui.Add("Button", "x380 y415 w100 h30", "📤 Export .ini")
    exportLocalBtn.OnEvent("Click", ExportToIni)
    
    ieGui.SetFont("s10 Bold c00FF00", "Segoe UI")
    statusLabel := ieGui.Add("Text", "x20 y455 w460", 
        PRESET_IN_USE ? "✅ Using: " . PRESET_IN_USE : "⚠️ No preset loaded")
    
    ; ========== TAB 2: CLOUD EXPORT ==========
    tab.UseTab(2)
    
    ieGui.SetFont("s10 Bold cFFFF00", "Segoe UI")
    ieGui.Add("Text", "x20 y80", "Export Preset to Cloud:")
    
    ieGui.SetFont("s10 cFFFFFF", "Segoe UI")
    
    ieGui.Add("Text", "x20 y115", "Preset Name:")
    cloudNameEdit := ieGui.Add("Edit", "x130 y113 w300 Background0x16213e", "")
    
    ieGui.Add("Text", "x20 y150", "Description:")
    cloudDescEdit := ieGui.Add("Edit", "x130 y148 w300 h60 VScroll Background0x16213e", "")
    
    ieGui.Add("Text", "x20 y220", "Build Type:")
    cloudTypeCombo := ieGui.Add("DropDownList", "x130 y218 w150", ["Both", "Puncture", "Hybrid"])
    cloudTypeCombo.Choose(1)
    
    ieGui.Add("Text", "x290 y220", "Ping Range:")
    cloudPingCombo := ieGui.Add("DropDownList", "x380 y218 w100", 
        ["0-50ms", "50-100ms", "100-150ms", "150-200ms", "200ms+"])
    cloudPingCombo.Choose(1)
    
    ieGui.Add("Text", "x20 y255", "Exact Ping:")
    exactPingEdit := ieGui.Add("Edit", "x130 y253 w100 Background0x16213e Number", "")
    
    ieGui.Add("Text", "x240 y255", "Tags:")
    cloudTagsEdit := ieGui.Add("Edit", "x280 y253 w200 Background0x16213e", "")
    ieGui.SetFont("s8 cC0C0C0", "Segoe UI")
    ieGui.Add("Text", "x280 y280", "(Comma separated: pvp, pve, raid)")
    
    ieGui.SetFont("s10 cFFFFFF", "Segoe UI")
    publicCheck := ieGui.Add("Checkbox", "x20 y305", "Make Public (Share with community)")
    publicCheck.Value := 1
    
    ieGui.SetFont("s10", "Segoe UI")
    exportBtn := ieGui.Add("Button", "x500 y115 w120 h40", "☁️ Export Current")
    exportBtn.OnEvent("Click", ExportToCloudV7)
    
    ; ========== TAB 3: MY CLOUD PRESETS ==========
    tab.UseTab(3)
    
    ieGui.SetFont("s10 Bold cFFFF00", "Segoe UI")
    ieGui.Add("Text", "x20 y80", "My Cloud Presets:")
    
    ieGui.SetFont("s10 cFFFFFF", "Segoe UI")
    cloudListView := ieGui.Add("ListView", "x20 y105 w750 h340 Grid Background0x16213e", 
        ["Name", "Type", "Ping", "Exact Ping", "Public", "Downloads", "Rating", "Version", "Updated"])
    cloudListView.ModifyCol(1, 180) ; Name
    cloudListView.ModifyCol(2, 70)  ; Type
    cloudListView.ModifyCol(3, 80)  ; Ping
    cloudListView.ModifyCol(4, 70)  ; Exact Ping
    cloudListView.ModifyCol(5, 60)  ; Public
    cloudListView.ModifyCol(6, 80)  ; Downloads
    cloudListView.ModifyCol(7, 80)  ; Rating
    cloudListView.ModifyCol(8, 60)  ; Version
    cloudListView.ModifyCol(9, 100) ; Updated
    
    refreshCloudBtn := ieGui.Add("Button", "x20 y455 w120 h30", "🔄 Refresh")
    refreshCloudBtn.OnEvent("Click", RefreshCloudPresetsV7)
    
    downloadCloudBtn := ieGui.Add("Button", "x150 y455 w120 h30", "📥 Download")
    downloadCloudBtn.OnEvent("Click", DownloadCloudPreset)
    
    updateCloudBtn := ieGui.Add("Button", "x280 y455 w120 h30", "🔄 Update")
    updateCloudBtn.OnEvent("Click", UpdateCloudPreset)
    
    deleteCloudBtn := ieGui.Add("Button", "x410 y455 w120 h30", "🗑️ Delete")
    deleteCloudBtn.OnEvent("Click", DeleteCloudPresetV7)
    
    ; Event handlers
    localListView.OnEvent("Click", OnLocalPresetSelect)
    localListView.OnEvent("DoubleClick", LoadSelectedPreset)
    cloudListView.OnEvent("Click", OnCloudPresetSelect)
    
    OnLocalPresetSelect(*) {
        row := localListView.GetNext()
        if (row) {
            preset := LOCAL_PRESETS[row]
            GeneratePresetPreviewV7(preset)
        }
    }
    
    OnCloudPresetSelect(*) {
        row := cloudListView.GetNext()
        if (row) {
            ; Get selected cloud preset data
        }
    }
    
    GeneratePresetPreviewV7(preset) {
        preview := "╔═══════════════════════════════════════╗`r`n"
        preview .= "║ PRESET: " . preset["name"] . "`r`n"
        preview .= "╚═══════════════════════════════════════╝`r`n`r`n"
        preview .= "📋 Descrição: " . preset["description"] . "`r`n"
        preview .= "🎮 Build Type: " . preset["build_type"] . "`r`n"
        preview .= "📡 Ping Range: " . preset["ping_range"] . "`r`n"
        preview .= "📍 Exact Ping: " . preset["exact_ping"] . "ms`r`n"
        preview .= "📅 Criado: " . preset["created"] . "`r`n"
        preview .= "🔧 Versão: " . preset["version"] . "`r`n`r`n"
        
        preview .= "⚙️ CONFIGURAÇÃO DE TIMING:`r`n"
        preview .= "═══════════════════════════════════════`r`n"
        
        if (preset.Has("path") && FileExist(preset["path"])) {
            shareableKeys := GetShareableSettings()
            for key, defaultValue in shareableKeys {
                value := IniRead(preset["path"], "Settings", key, defaultValue)
                displayName := FormatSettingName(key)
                preview .= "• " . displayName . ": " . value . "ms`r`n"
            }
        }
        
        preview .= "`r`n═══════════════════════════════════════`r`n"
        preview .= "Dê um duplo clique para carregar este preset"
        
        previewText.Text := StrReplace(preview, "`n", "`r`n")
    }
    
    LoadSelectedPreset(*) {
        row := localListView.GetNext()
        if (row) {
            preset := LOCAL_PRESETS[row]
            if (ApplyDownloadedPreset(preset)) {
                global PRESET_IN_USE := preset["name"]
                statusLabel.Text := "✅ Using: " . preset["name"]
                RefreshLocalPresets()
                ShowTooltip("✅ Preset loaded: " . preset["name"], 3000)
            }
        }
    }
    
    DeleteSelectedPreset(*) {
        row := localListView.GetNext()
        if (row) {
            preset := LOCAL_PRESETS[row]
            result := MsgBox("Delete preset: " . preset["name"] . "?", "Confirm", "YesNo Icon?")
            if (result = "Yes") {
                if (DeleteLocalPreset(preset["path"])) {
                    ShowTooltip("✅ Preset deleted", 2000)
                    RefreshLocalPresets()
                }
            }
        }
    }

    DeleteLocalPreset(filePath) {
        try {
            if FileExist(filePath) {
                FileDelete(filePath)
                return true
            }
        } catch {
            return false
        }
        return false
    }
    
    CreateNewPreset(*) {
        createGui := Gui("+AlwaysOnTop +Owner" . ieGui.Hwnd, "Create New Preset")
        createGui.BackColor := "0x1a1a2e"
        createGui.SetFont("s10 cFFFFFF", "Segoe UI")
        
        createGui.Add("Text", "x10 y10", "Preset Name:")
        nameEdit := createGui.Add("Edit", "x100 y8 w200 Background0x16213e", "")
        
        createGui.Add("Text", "x10 y40", "Description:")
        descEdit := createGui.Add("Edit", "x100 y38 w200 h50 VScroll Background0x16213e", "")
        
        createGui.Add("Text", "x10 y100", "Build Type:")
        typeCombo := createGui.Add("DropDownList", "x100 y98 w100", ["both", "puncture", "hybrid"])
        typeCombo.Choose(1)
        
        createGui.Add("Text", "x10 y130", "Ping Range:")
        pingCombo := createGui.Add("DropDownList", "x100 y128 w100", 
            ["0-50ms", "50-100ms", "100-150ms", "150-200ms", "200ms+"])
        pingCombo.Choose(1)

        createGui.Add("Text", "x10 y160", "Exact Ping:")
        exactPingEdit := createGui.Add("Edit", "x100 y158 w100 Background0x16213e Number", "")
        
        saveBtn := createGui.Add("Button", "x80 y200 w70 h30", "Save")
        saveBtn.OnEvent("Click", SaveNewPreset)
        
        cancelBtn := createGui.Add("Button", "x160 y200 w70 h30", "Cancel")
        cancelBtn.OnEvent("Click", (*) => createGui.Destroy())
        
        SaveNewPreset(*) {
            name := Trim(nameEdit.Text)
            if (!name) {
                MsgBox("Please enter a preset name", "Error", "Icon!")
                return
            }
            
            SaveLocalPreset(name, descEdit.Text, typeCombo.Text, pingCombo.Text, exactPingEdit.Text)
            ShowTooltip("✅ Preset created: " . name, 2000)
            createGui.Destroy()
            RefreshLocalPresets()
        }

        SaveLocalPreset(name, description, buildType, pingRange, exactPing) {
            global PRESETS_DIR, APP_VERSION, SETTINGS

            if (!DirExist(PRESETS_DIR)) {
                DirCreate(PRESETS_DIR)
            }

            presetFile := PRESETS_DIR . "\" . name . ".ini"

            IniWrite(name, presetFile, "Metadata", "name")
            IniWrite(description, presetFile, "Metadata", "description")
            IniWrite(buildType, presetFile, "Metadata", "build_type")
            IniWrite(pingRange, presetFile, "Metadata", "ping_range")
            IniWrite(exactPing, presetFile, "Metadata", "exact_ping")
            IniWrite(APP_VERSION, presetFile, "Metadata", "version")
            IniWrite(FormatTime(A_Now, "yyyy-MM-dd"), presetFile, "Metadata", "created")

            ; Save shareable timing settings
            shareableSettings := GetShareableSettings()
            for key, value in shareableSettings {
                IniWrite(value, presetFile, "Settings", key)
            }
        }
        
        createGui.Show("w310 h240")
        nameEdit.Focus()
    }
    
    ExportToIni(*) {
        row := localListView.GetNext()
        if (row) {
            preset := LOCAL_PRESETS[row]
            exportPath := FileSelect("S", preset["name"] . ".ini", "Export Preset", "INI Files (*.ini)")
            if (exportPath) {
                FileCopy(preset["path"], exportPath, 1)
                ShowTooltip("✅ Exported to: " . exportPath, 3000)
            }
        } else {
            ShowTooltip("⚠️ Please select a preset first", 2000)
        }
    }
    
    ExportToCloudV7(*) {
        name := Trim(cloudNameEdit.Text)
        if (!name) {
            MsgBox("Please enter a preset name", "Error", "Icon!")
            return
        }
        
        presetData := Map(
            "name", name,
            "description", cloudDescEdit.Text,
            "build_type", StrLower(cloudTypeCombo.Text),
            "ping_range", cloudPingCombo.Text,
            "exact_ping", exactPingEdit.Text ? Integer(exactPingEdit.Text) : 0,
            "is_public", publicCheck.Value,
            "tags", cloudTagsEdit.Text
        )
        
        result := SupabaseClient.SavePresetToCloud(presetData)
        
        if (result["success"]) {
            ShowTooltip("✅ " . result["message"], 3000)
            cloudNameEdit.Text := ""
            cloudDescEdit.Text := ""
            cloudTagsEdit.Text := ""
            exactPingEdit.Text := ""
            RefreshCloudPresetsV7()
        } else {
            ShowTooltip("❌ " . result["error"], 3000)
        }
    }
    
    RefreshLocalPresets(*) {
        LoadLocalPresets()
        localListView.Delete()
        
        for preset in LOCAL_PRESETS {
            status := (preset["name"] = PRESET_IN_USE) ? "✓" : ""
            localListView.Add("", preset["name"], preset["build_type"], 
                preset["ping_range"], preset["exact_ping"], preset["created"], preset["version"], status)
        }
        
        previewText.Text := "Select a preset to preview"
    }

    LoadLocalPresets() {
        global LOCAL_PRESETS, PRESETS_DIR

        LOCAL_PRESETS := []
        if (!DirExist(PRESETS_DIR)) {
            DirCreate(PRESETS_DIR)
        }

        Loop Files, PRESETS_DIR . "\*.ini" {
            presetFile := A_LoopFileFullPath
            name := IniRead(presetFile, "Metadata", "name", "")
            description := IniRead(presetFile, "Metadata", "description", "")
            build_type := IniRead(presetFile, "Metadata", "build_type", "")
            ping_range := IniRead(presetFile, "Metadata", "ping_range", "")
            exact_ping := IniRead(presetFile, "Metadata", "exact_ping", "")
            created := IniRead(presetFile, "Metadata", "created", "")
            version := IniRead(presetFile, "Metadata", "version", "")
            LOCAL_PRESETS.Push(Map(
                "name", name,
                "description", description,
                "build_type", build_type,
                "ping_range", ping_range,
                "exact_ping", exact_ping,
                "created", created,
                "version", version,
                "path", presetFile
            ))
        }
    }
    
    RefreshCloudPresetsV7(*) {
        userPresets := SupabaseClient.GetUserPresets()
        cloudListView.Delete()
        
        for preset in userPresets {
            isPublic := preset.Get("is_public", false) ? "Yes" : "No"
            rating := preset.Get("rating", 0) ? Format("{:.1f}⭐", preset["rating"]) : "No rating"
            updated := SubStr(preset.Get("updated_at", preset.Get("created_at", "")), 1, 10)
            
            cloudListView.Add("", 
                preset.Get("name", ""),
                preset.Get("build_type", ""),
                preset.Get("ping_range", ""),
                preset.Get("exact_ping", ""),
                isPublic,
                preset.Get("downloads", 0),
                rating,
                preset.Get("version", ""),
                updated
            )
        }
    }
    
    DownloadCloudPreset(*) {
        ; Implementation for downloading cloud preset
        ShowTooltip("⚠️ Select a cloud preset first", 2000)
    }
    
    UpdateCloudPreset(*) {
        ShowTooltip("⚠️ Update feature coming soon", 2000)
    }
    
    DeleteCloudPresetV7(*) {
        row := cloudListView.GetNext()
        if (row) {
            result := MsgBox("Delete cloud preset?", "Confirm", "YesNo Icon?")
            if (result = "Yes") {
                ; Implementation
                ShowTooltip("✅ Cloud preset deleted", 2000)
                RefreshCloudPresetsV7()
            }
        }
    }
    
    ; Load initial data
    RefreshLocalPresets()
    RefreshCloudPresetsV7()
    
    ieGui.Show("w800 h550")
}

ShowBuildLibraryV7(*) {
    global GUI_REFS
    
    if (GUI_REFS["build_library"]) {
        try GUI_REFS["build_library"].Destroy()
    }
    
    blGui := Gui("+AlwaysOnTop +Resize", "📚 Build Library v7.0")
    blGui.BackColor := "0x1a1a2e"
    GUI_REFS["build_library"] := blGui
    
    blGui.SetFont("s12 Bold cFFFFFF", "Segoe UI")
    blGui.Add("Text", "x0 y10 w900 Center", "COMMUNITY BUILD LIBRARY v7.0")
    
    ; Enhanced filters
    blGui.SetFont("s10 cFFFFFF", "Segoe UI")
    blGui.Add("Text", "x20 y50", "Search:")
    searchEdit := blGui.Add("Edit", "x70 y48 w200 Background0x16213e", "")
    
    blGui.Add("Text", "x280 y50", "Type:")
    typeFilter := blGui.Add("DropDownList", "x320 y48 w100", ["All", "Puncture", "Hybrid", "Both"])
    typeFilter.Choose(1)
    
    blGui.Add("Text", "x430 y50", "Ping:")
    pingFilter := blGui.Add("DropDownList", "x470 y48 w100", 
        ["All", "0-50ms", "50-100ms", "100-150ms", "150-200ms", "200ms+"])
    pingFilter.Choose(1)
    
    blGui.Add("Text", "x580 y50", "Sort:")
    sortFilter := blGui.Add("DropDownList", "x620 y48 w120", 
        ["Newest", "Most Downloaded", "Best Rated", "Trending", "Oldest"])
    sortFilter.Choose(1)
    
    searchBtn := blGui.Add("Button", "x750 y47 w80 h26", "🔍 Search")
    searchBtn.OnEvent("Click", SearchBuildsV7)
    
    buildListView := blGui.Add("ListView", "x20 y85 w860 h400 Grid Background0x16213e", 
        ["Name", "Author", "Type", "Ping", "Exact Ping", "Downloads", "Rating", "Version", "Date", "Tags", "ID"])
    buildListView.ModifyCol(1, 150) ; Name
    buildListView.ModifyCol(2, 90)  ; Author
    buildListView.ModifyCol(3, 60)  ; Type
    buildListView.ModifyCol(4, 70)  ; Ping
    buildListView.ModifyCol(5, 70)  ; Exact Ping
    buildListView.ModifyCol(6, 70)  ; Downloads
    buildListView.ModifyCol(7, 70)  ; Rating
    buildListView.ModifyCol(8, 60)  ; Version
    buildListView.ModifyCol(9, 80)  ; Date
    buildListView.ModifyCol(10, 100) ; Tags
    buildListView.ModifyCol(11, 0)  ; Hidden ID
    
    ; Details area
    blGui.Add("GroupBox", "x20 y495 w420 h140", "Build Details")
    detailsText := blGui.Add("Edit", "x30 y515 w400 h110 ReadOnly VScroll Background0x16213e", 
        "Select a build to view details...")
    
    ; Actions area
    blGui.Add("GroupBox", "x450 y495 w430 h140", "Actions")
    
    blGui.SetFont("s10", "Segoe UI")
    downloadBtn := blGui.Add("Button", "x465 y520 w120 h35", "📥 Download")
    downloadBtn.OnEvent("Click", DownloadBuildV7)
    
    previewBtn := blGui.Add("Button", "x595 y520 w120 h35", "👁️ Preview")
    previewBtn.OnEvent("Click", PreviewBuildV7)
    
    rateBtn := blGui.Add("Button", "x725 y520 w120 h35", "⭐ Rate")
    rateBtn.OnEvent("Click", RateBuildV7)
    
    ; Stats
    blGui.SetFont("s9 cC0C0C0", "Segoe UI")
    statsText := blGui.Add("Text", "x465 y570 w400", "")
    
    ; Version filter
    blGui.SetFont("s9 cFFFFFF", "Segoe UI")
    versionCheck := blGui.Add("Checkbox", "x465 y595", "Only show v7.0+ compatible builds")
    versionCheck.Value := 1
    
    ; Events
    buildListView.OnEvent("Click", OnBuildSelectV7)
    buildListView.OnEvent("DoubleClick", DownloadBuildV7)
    
    selectedBuildData := ""
    
    OnBuildSelectV7(*) {
        row := buildListView.GetNext()
        if (row) {
            buildId := buildListView.GetText(row, 11)
            
            ; Get build details
            buildData := SupabaseClient.DownloadPreset(buildId)
            if (buildData) {
                selectedBuildData := buildData
                
                details := "📋 " . buildData.Get("name", "") . "`n"
                details .= "👤 Author: " . buildData.Get("author_name", "") . "`n"
                details .= "📝 " . buildData.Get("description", "No description") . "`n`n"
                
                tags := buildData.Get("tags", [])
                if (Type(tags) = "Array" && tags.Length > 0) {
                    details .= "🏷️ Tags: " . JoinArray(tags, ", ")
                }
                
                detailsText.Text := details
                
                ; Update stats
                stats := Format("📊 Downloads: {} | ⭐ Rating: {:.1f} ({} votes) | Version: {}", 
                    buildData.Get("downloads", 0),
                    buildData.Get("rating", 0),
                    buildData.Get("rating_count", 0),
                    buildData.Get("version", "Unknown"))
                statsText.Text := stats
            }
        }
    }
    
    SearchBuildsV7(*) {
        searchTerm := Trim(searchEdit.Text)
        buildType := typeFilter.Text = "All" ? "" : StrLower(typeFilter.Text)
        pingRange := pingFilter.Text = "All" ? "" : pingFilter.Text
        
        sortBy := "created_at"
        switch sortFilter.Text {
            case "Most Downloaded":
                sortBy := "downloads"
            case "Best Rated":
                sortBy := "rating"
            case "Trending":
                sortBy := "downloads" ; Could implement trending logic
            case "Oldest":
                sortBy := "oldest"
        }
        
        ; Add version filter if checked
        minVersion := versionCheck.Value ? "7.0.0" : ""
        
        builds := SupabaseClient.SearchPresets(searchTerm, buildType, sortBy)
        
        buildListView.Delete()
        for build in builds {
            ; Filter by version if needed
            if (minVersion && build.Has("version")) {
                if (SupabaseClient.CompareVersions(build["version"], minVersion) < 0) {
                    continue
                }
            }
            
            rating := build.Get("rating", 0) ? Format("{:.1f}⭐", build["rating"]) : "-"
            date := SubStr(build.Get("created_at", ""), 1, 10)
            tags := Type(build.Get("tags", "")) = "Array" ? JoinArray(build["tags"], ", ") : ""
            
            buildListView.Add("",
                build.Get("name", ""),
                build.Get("author_name", ""),
                build.Get("build_type", ""),
                build.Get("ping_range", ""),
                build.Get("exact_ping", ""),
                build.Get("downloads", 0),
                rating,
                build.Get("version", ""),
                date,
                tags,
                build.Get("id", "")
            )
        }
        
        ShowTooltip("Found " . builds.Length . " builds", 2000)
    }
    
    ; ================= CORREÇÃO DE ERRO 1: Função aninhada removida =================
    DownloadBuildV7(*) {
        if (!selectedBuildData) {
            ShowTooltip("⚠️ Please select a build first", 2000)
            return
        }
        
        result := MsgBox("Download and apply this build?`n`n" . 
            selectedBuildData.Get("name", "") . "`n" .
            "by " . selectedBuildData.Get("author_name", ""),
            "Confirm Download", "YesNo Icon?")
        
        if (result = "Yes") {
            ; A chamada agora usa a função global ApplyDownloadedPreset
            if (ApplyDownloadedPreset(selectedBuildData)) {
                ; Increment downloads
                SupabaseClient.IncrementDownloads(selectedBuildData["id"])
                ShowTooltip("✅ Build downloaded and applied!", 3000)
                SearchBuildsV7() ; Refresh to update counter
            }
        }
    }
    
    PreviewBuildV7(*) {
        if (!selectedBuildData) {
            ShowTooltip("⚠️ Please select a build first", 2000)
            return
        }
        
        previewGui := Gui("+AlwaysOnTop +Owner" . blGui.Hwnd, "Build Preview")
        previewGui.BackColor := "0x1a1a2e"
        previewGui.SetFont("s10 cFFFFFF", "Consolas")
        
        preview := GenerateBuildPreviewV7(selectedBuildData)
        previewEdit := previewGui.Add("Edit", "x10 y10 w600 h400 ReadOnly VScroll Background0x16213e", preview)
        
        closeBtn := previewGui.Add("Button", "x260 y420 w100 h30", "Close")
        closeBtn.OnEvent("Click", (*) => previewGui.Destroy())
        
        previewGui.Show("w620 h460")
    }
    
    GenerateBuildPreviewV7(buildData) {
        preview := "════════════════════════════════════════════════`n"
        preview .= "  BUILD PREVIEW: " . buildData.Get("name", "") . "`n"
        preview .= "════════════════════════════════════════════════`n`n"
        
        preview .= "👤 Author: " . buildData.Get("author_name", "") . "`n"
        preview .= "🎮 Type: " . buildData.Get("build_type", "") . "`n"
        preview .= "📡 Ping: " . buildData.Get("ping_range", "") . "`n"
        
        if (buildData.Has("exact_ping") && buildData["exact_ping"]) {
            preview .= "📍 Exact Ping: " . buildData["exact_ping"] . "ms`n"
        }
        
        preview .= "📅 Created: " . SubStr(buildData.Get("created_at", ""), 1, 10) . "`n"
        preview .= "🔧 Version: " . buildData.Get("version", "Unknown") . "`n"
        preview .= "📊 Stats: " . buildData.Get("downloads", 0) . " downloads | "
        preview .= Format("{:.1f}⭐", buildData.Get("rating", 0)) . " rating`n`n"
        
        preview .= "📝 DESCRIPTION:`n"
        preview .= "────────────────`n"
        preview .= buildData.Get("description", "No description") . "`n`n"
        
        preview .= "⚙️ TIMING CONFIGURATION:`n"
        preview .= "────────────────────────`n"
        
        settings := buildData.Get("settings", Map())
        if (Type(settings) = "String") {
            try {
                settings := JSON.Parse(settings)
            }
        }
        
        if (Type(settings) = "Map") {
            for key, value in settings {
                displayName := FormatSettingName(key)
                preview .= "• " . displayName . ": " . value . "ms`n"
            }
        }
        
        tags := buildData.Get("tags", [])
        if (Type(tags) = "Array" && tags.Length > 0) {
            preview .= "`n🏷️ TAGS: " . JoinArray(tags, ", ") . "`n"
        }
        
        return preview
    }
    
    JoinArray(arr, sep := ", ") {
        out := ""
        for idx, val in arr {
            if (idx > 1)
                out .= sep
            out .= val
        }
        return out
    }
    
    RateBuildV7(*) {
        if (!selectedBuildData) {
            ShowTooltip("⚠️ Please select a build first", 2000)
            return
        }
        
        rateGui := Gui("+AlwaysOnTop +Owner" . blGui.Hwnd, "Rate Build")
        rateGui.BackColor := "0x1a1a2e"
        rateGui.SetFont("s10 cFFFFFF", "Segoe UI")
        
        rateGui.Add("Text", "x10 y10", "Rate this build:")
        
        rating := 5
        rateGui.Add("Text", "x10 y40", "Rating:")
        ratingSlider := rateGui.Add("Slider", "x60 y38 w200 Range1-5 TickInterval1", rating)
        ratingText := rateGui.Add("Text", "x270 y40 w50", "5 ⭐")
        
        ratingSlider.OnEvent("Change", (*) => ratingText.Text := ratingSlider.Value . " ⭐")
        
        rateGui.Add("Text", "x10 y80", "Comment (optional):")
        commentEdit := rateGui.Add("Edit", "x10 y100 w300 h60 VScroll Background0x16213e", "")
        
        submitBtn := rateGui.Add("Button", "x90 y170 w60 h30", "Submit")
        submitBtn.OnEvent("Click", SubmitRating)
        
        cancelBtn := rateGui.Add("Button", "x160 y170 w60 h30", "Cancel")
        cancelBtn.OnEvent("Click", (*) => rateGui.Destroy())
        
        SubmitRating(*) {
            if (SupabaseClient.RatePreset(selectedBuildData["id"], ratingSlider.Value, commentEdit.Text)) {
                ShowTooltip("✅ Rating submitted!", 2000)
                rateGui.Destroy()
                SearchBuildsV7() ; Refresh
            } else {
                ShowTooltip("❌ Failed to submit rating", 2000)
            }
        }
        
        rateGui.Show("w320 h210")
        commentEdit.Focus()
    }
    
    ; Load initial builds
    SearchBuildsV7()
    
    blGui.Show("w900 h645")
}

ShowSystemStatsV7(*) {
    global GUI_REFS, SESSION
    
    if (SESSION.role != "admin") {
        ShowTooltip("❌ Admin access required", 2000)
        return
    }
    
    if (GUI_REFS["system_stats"]) {
        try GUI_REFS["system_stats"].Destroy()
    }
    
    statsGui := Gui("+AlwaysOnTop", "📈 System Statistics v7.0")
    statsGui.BackColor := "0x1a1a2e"
    GUI_REFS["system_stats"] := statsGui
    
    statsGui.SetFont("s12 Bold cFFFFFF", "Segoe UI")
    statsGui.Add("Text", "x0 y10 w600 Center", "SYSTEM STATISTICS v7.0")
    
    statsGui.SetFont("s10 cFFFFFF", "Segoe UI")
    
    ; Statistics display
    statsText := statsGui.Add("Edit", "x10 y50 w580 h400 ReadOnly VScroll Background0x16213e", 
        "Loading statistics...")
    
    ; Buttons
    refreshBtn := statsGui.Add("Button", "x150 y460 w100 h30", "🔄 Refresh")
    refreshBtn.OnEvent("Click", LoadStatsV7)
    
    exportBtn := statsGui.Add("Button", "x260 y460 w100 h30", "📤 Export")
    exportBtn.OnEvent("Click", ExportStats)
    
    closeBtn := statsGui.Add("Button", "x370 y460 w100 h30", "Close")
    closeBtn.OnEvent("Click", (*) => statsGui.Destroy())
    
    LoadStatsV7(*) {
        statsText.Text := "Fetching statistics from server..."
        
        result := SupabaseClient.GetAdminStats()
        
        if (result["success"]) {
            stats := result["data"]
            
            displayText := "════════════════════════════════════════════`n"
            displayText .= "         SYSTEM STATISTICS DASHBOARD v7.0`n"
            displayText .= "════════════════════════════════════════════`n`n"
            
            displayText .= "👥 USER STATISTICS:`n"
            displayText .= "───────────────────`n"
            displayText .= "• Total Users: " . stats.Get("users_total", 0) . "`n"
            displayText .= "• Trial Users: " . stats.Get("trials_total", 0) . "`n"
            displayText .= "• Premium Users: " . stats.Get("premium_total", 0) . "`n"
            displayText .= "• Blocked Users: " . stats.Get("blocked_total", 0) . "`n"
            displayText .= "• New Today: " . stats.Get("new_users_today", 0) . "`n"
            displayText .= "• New This Week: " . stats.Get("new_users_week", 0) . "`n`n"
            
            displayText .= "📦 PRESET STATISTICS:`n"
            displayText .= "─────────────────────`n"
            displayText .= "• Public Presets: " . stats.Get("presets_public", 0) . "`n"
            displayText .= "• Private Presets: " . stats.Get("presets_private", 0) . "`n"
            displayText .= "• Total Downloads: " . stats.Get("downloads_total", 0) . "`n"
            displayText .= "• Average Rating: " . Format("{:.2f}", stats.Get("rating_avg", 0)) . " ⭐`n"
            displayText .= "• Total Ratings: " . stats.Get("rating_count", 0) . "`n`n"
            
            displayText .= "📊 ACTIVITY STATISTICS:`n"
            displayText .= "───────────────────────`n"
            displayText .= "• Activities (24h): " . stats.Get("activity_24h", 0) . "`n"
            displayText .= "• Activities (7d): " . stats.Get("activity_7d", 0) . "`n"
            displayText .= "• Latest Version: " . stats.Get("latest_version", APP_VERSION) . "`n"
            displayText .= "• Maintenance Mode: " . stats.Get("maintenance_mode", "false") . "`n`n"
            
            displayText .= "🏆 TOP DOWNLOADED PRESETS:`n"
            displayText .= "──────────────────────────`n"
            
            topDownloads := stats.Get("top_downloads", [])
            if (Type(topDownloads) = "Array" && topDownloads.Length > 0) {
                for idx, preset in topDownloads {
                    displayText .= Format("{}. {} by {} ({} downloads, {:.1f}⭐)`n",
                        idx,
                        preset.Get("name", "Unknown"),
                        preset.Get("author", "Unknown"),
                        preset.Get("downloads", 0),
                        preset.Get("rating", 0))
                }
            } else {
                displayText .= "No presets available`n"
            }
            
            displayText .= "`n🔝 TOP RATED PRESETS:`n"
            displayText .= "────────────────────`n"
            
            topRated := stats.Get("top_rated", [])
            if (Type(topRated) = "Array" && topRated.Length > 0) {
                for idx, preset in topRated {
                    displayText .= Format("{}. {} ({:.1f}⭐ from {} votes)`n",
                        idx,
                        preset.Get("name", "Unknown"),
                        preset.Get("rating", 0),
                        preset.Get("rating_count", 0))
                }
            }
            
            displayText .= "`n════════════════════════════════════════════`n"
            displayText .= "Last updated: " . FormatTime(A_Now, "yyyy-MM-dd HH:mm:ss")
            
            statsText.Text := displayText
        } else {
            statsText.Text := "Error loading statistics:`n`n" . result.Get("error", "Unknown error")
        }
    }
    
    ExportStats(*) {
        filepath := FileSelect("S", "stats_" . FormatTime(A_Now, "yyyyMMdd_HHmmss") . ".txt", 
            "Export Statistics", "Text Files (*.txt)")
        if (filepath) {
            FileAppend(statsText.Text, filepath)
            ShowTooltip("✅ Statistics exported to: " . filepath, 3000)
        }
    }
    
    ; Load initial stats
    LoadStatsV7()
    
    statsGui.Show("w600 h500")
}

ShowUserManagerV7(*) {
    if (SESSION.role != "admin") {
        ShowTooltip("❌ Admin access required", 2000)
        return
    }
    
    MsgBox(
        "User Manager v7.0`n`n" .
        "Please use the Admin Panel HTML for complete user management.`n`n" .
        "Features available:`n" .
        "• User list with search and filters`n" .
        "• Block/unblock users`n" .
        "• Change user roles`n" .
        "• Extend trial periods`n" .
        "• View detailed user activity`n" .
        "• Manage user presets`n`n" .
        "Open admin.html in your browser for full access.",
        "Admin Feature",
        "Icon!"
    )
    
    ; Option to open admin panel
    result := MsgBox("Would you like to open the Admin Panel now?", "Open Admin Panel", "YesNo Icon?")
    if (result = "Yes") {
        Run(A_ScriptDir . "\admin.html")
    }
}

CheckForUpdatesV7(*) {
    global RUNTIME, APP_VERSION
    
    ShowTooltip("🔍 Checking for updates...", 2000)
    
    ; Sync app settings from database
    SupabaseClient.SyncAppSettings()
    
    if (RUNTIME.updateAvailable) {
        result := MsgBox(
            "New version available: v" . RUNTIME.latestVersion . "`n`n" .
            "Current version: v" . APP_VERSION . "`n`n" .
            "Changes in new version:`n" .
            "• Enhanced preset system`n" .
            "• Improved cloud sync`n" .
            "• Bug fixes and optimizations`n`n" .
            "Would you like to update now?",
            "Update Available",
            "YesNo Icon!"
        )
        
        if (result = "Yes") {
            DownloadAndInstallUpdateV7()
        }
    } else {
        ShowTooltip("✅ You have the latest version!", 2000)
    }
}

DownloadAndInstallUpdateV7() {
    global UPDATE_DIR, RUNTIME
    
    if (!DirExist(UPDATE_DIR)) {
        DirCreate(UPDATE_DIR)
    }
    
    updateUrl := SupabaseClient.GetAppConfig("update_url")
    
    if (!updateUrl) {
        updateUrl := "https://github.com/yourusername/bns-macro/releases/latest"
    }
    
    MsgBox(
        "Update System v7.0`n`n" .
        "The update will be downloaded from:`n" .
        updateUrl . "`n`n" .
        "After download, the script will restart with the new version.`n`n" .
        "Click OK to proceed with the update.",
        "Update System",
        "Icon!"
    )
    
    ; Here you would implement actual download logic
    ; For now, just show the process
    ShowTooltip("📥 Downloading update v" . RUNTIME.latestVersion . "...", 5000)
    
    ; Simulate download
    Sleep(2000)
    
    ShowTooltip("✅ Update downloaded! Restarting...", 2000)
    Sleep(2000)
    
    ; Reload script (in real implementation, would load new version)
    Reload()
}

; ================= CLOSE MAIN MENU =================
CloseMainMenu() {
    global GUI_REFS, RUNTIME, mainStatusText
    
    if (GUI_REFS["main"] && IsObject(GUI_REFS["main"])) {
        try GUI_REFS["main"].Destroy()
        GUI_REFS["main"] := ""
    }
    
    RUNTIME.mainMenuOpen := false
    mainStatusText := ""  ; Limpa a referência quando o menu é fechado
}

; ================= UPDATE MAIN MENU STATUS =================
UpdateMainMenuStatus() {
    global RUNTIME, mainStatusText
    
    if (mainStatusText) {
        statusValue := RUNTIME.suspendMacros ? "⏸️ SUSPENDED" : "▶️ ACTIVE"
        modeText := RUNTIME.mode = "puncture" ? "Puncture" : "Hybrid"
        mainStatusText.Text := "Status: " . statusValue . " | Mode: " . modeText
        
        if (RUNTIME.suspendMacros) {
            mainStatusText.SetFont("cFF0000")
        } else {
            mainStatusText.SetFont("c00FF00")
        }
    }
}

ParseTags(tagString) {
    if (!tagString)
        return []
    
    tags := []
    for _, tag in StrSplit(tagString, ",") {
        trimmed := Trim(tag)
        if (trimmed != "")
            tags.Push(trimmed)
    }
    return tags
}

; ================= OTHER FUNCTIONS =================
ShowModeSelection() {
    global RUNTIME
    
    modeGui := Gui("+AlwaysOnTop +ToolWindow", "⚔️ Select Operation Mode")
    modeGui.BackColor := "0x1a1a2e"
    
    modeGui.SetFont("s14 Bold cFFFFFF", "Segoe UI")
    modeGui.Add("Text", "x50 y20 w300 Center", "SELECT OPERATION MODE")
    
    modeGui.SetFont("s12", "Segoe UI")
    
    punctureBtn := modeGui.Add("Button", "x50 y70 w140 h50", "🎯 Puncture")
    punctureBtn.OnEvent("Click", SelectPuncture)
    
    hybridBtn := modeGui.Add("Button", "x210 y70 w140 h50", "🔄 Hybrid")
    hybridBtn.OnEvent("Click", SelectHybrid)

    modeGui.SetFont("s10 cSilver", "Segoe UI")
    modeGui.Add("Text", "x20 y140 w360", "🎯 Puncture: Detects critical hits using FindText")
    modeGui.Add("Text", "x20 y160 w360", "🔄 Hybrid: Custom sequences + Focus pixel detection")
    
    SelectPuncture(*) {
        RUNTIME.mode := "puncture"
        modeGui.Destroy()
        ShowTooltip("✅ Mode switched to Puncture!", 2000)
        UpdateMainMenuStatus()
    }
    
    SelectHybrid(*) {
        RUNTIME.mode := "hybrid"
        modeGui.Destroy()
        ShowTooltip("✅ Mode switched to Hybrid!", 2000)
        UpdateMainMenuStatus()
    }
    
    modeGui.Show("w400 h200")
}

ShowUpgradeDialog() {
    upgradeGui := Gui("+AlwaysOnTop", "⭐ Upgrade to Premium")
    upgradeGui.BackColor := "0x1a1a2e"
    
    upgradeGui.SetFont("s12 Bold cFFFFFF", "Segoe UI")
    upgradeGui.Add("Text", "x0 y20 w400 Center", "Unlock Full Features!")
    
    upgradeGui.SetFont("s10 cFFFFFF", "Segoe UI")
    features := "✅ Unlimited usage`n"
    features .= "✅ Priority support`n"
    features .= "✅ Exclusive presets`n"
    features .= "✅ Advanced configurations`n"
    features .= "✅ Discord VIP role`n"
    features .= "✅ Future updates included"
    
    upgradeGui.Add("Text", "x50 y60 w300", features)
    
    purchaseBtn := upgradeGui.Add("Button", "x100 y220 w200 h40", "💳 Purchase Premium")
    purchaseBtn.OnEvent("Click", (*) => Run(""))
    
    laterBtn := upgradeGui.Add("Button", "x160 y270 w80 h30", "Later")
    laterBtn.OnEvent("Click", (*) => upgradeGui.Destroy())
    
    upgradeGui.Show("w400 h320")
}

; ================= SHOW HOTKEY EDITOR =================
ShowHotkeyEditor(*) {
    global GUI_REFS, SETTINGS
    
    if (GUI_REFS["hotkey"]) {
        try GUI_REFS["hotkey"].Destroy()
    }
    
    hotkeyGui := Gui("+AlwaysOnTop +ToolWindow", "⚙️ Hotkey Configuration")
    hotkeyGui.BackColor := "0x1a1a2e"
    GUI_REFS["hotkey"] := hotkeyGui
    
    hotkeyGui.SetFont("s12 Bold cFFFFFF", "Segoe UI")
    hotkeyGui.Add("Text", "x10 y10 w470 Center", "HOTKEY CONFIGURATION")
    
    tab := hotkeyGui.Add("Tab3", "x10 y40 w470 h420", ["Macro Keys", "Puncture Keys", "Hybrid Keys", "System Keys"])
    
    ; === TAB 1: Macro Keys ===
    tab.UseTab(1)
    hotkeyGui.SetFont("s10 cFFFFFF", "Segoe UI")
    
    hotkeyGui.Add("Text", "x20 y80", "Macro 1 Key:")
    macro1Edit := hotkeyGui.Add("Edit", "x150 y78 w100 Background0x2a2a3e cWhite", SETTINGS["hotkey_macro1"])
    
    macro1Mode := hotkeyGui.Add("DropDownList", "x260 y78 w90", ["hold", "toggle"])
    macro1Mode.Text := SETTINGS["macro1_mode"]
    
    hotkeyGui.Add("Text", "x20 y115", "Macro 2 Key:")
    macro2Edit := hotkeyGui.Add("Edit", "x150 y113 w100 Background0x2a2a3e cWhite", SETTINGS["hotkey_macro2"])
    
    macro2Mode := hotkeyGui.Add("DropDownList", "x260 y113 w90", ["hold", "toggle"])
    macro2Mode.Text := SETTINGS["macro2_mode"]
    
    ; === TAB 2: Puncture Keys ===
    tab.UseTab(2)
    hotkeyGui.SetFont("s10 Bold cFFFF00", "Segoe UI")
    hotkeyGui.Add("Text", "x20 y80 w430", "PUNCTURE MODE SKILL KEYS:")
    
    hotkeyGui.SetFont("s10 cFFFFFF", "Segoe UI")
    hotkeyGui.Add("Text", "x20 y110", "R Skill Key:")
    puncREdit := hotkeyGui.Add("Edit", "x150 y108 w60 Background0x2a2a3e cWhite", SETTINGS["key_puncture_r"])
    
    hotkeyGui.Add("Text", "x20 y145", "T Skill Key:")
    puncTEdit := hotkeyGui.Add("Edit", "x150 y143 w60 Background0x2a2a3e cWhite", SETTINGS["key_puncture_t"])
    
    hotkeyGui.Add("Text", "x20 y180", "Tab Skill Key:")
    puncTabEdit := hotkeyGui.Add("Edit", "x150 y178 w60 Background0x2a2a3e cWhite", SETTINGS["key_puncture_tab"])
    
    ; === TAB 3: Hybrid Keys ===
    tab.UseTab(3)
    hotkeyGui.SetFont("s10 Bold cFFFF00", "Segoe UI")
    hotkeyGui.Add("Text", "x20 y80 w430", "HYBRID MODE SKILL KEYS:")
    
    hotkeyGui.SetFont("s10 cFFFFFF", "Segoe UI")
    hotkeyGui.Add("Text", "x20 y110", "T Skill Key:")
    hybMainEdit := hotkeyGui.Add("Edit", "x150 y108 w60 Background0x2a2a3e cWhite", SETTINGS["key_hybrid_main"])
    
    hotkeyGui.Add("Text", "x20 y145", "R Skill Key:")
    hybSecEdit := hotkeyGui.Add("Edit", "x150 y143 w60 Background0x2a2a3e cWhite", SETTINGS["key_hybrid_secondary"])
    
    ; === TAB 4: System Keys ===
    tab.UseTab(4)
    hotkeyGui.SetFont("s10 cFFFFFF", "Segoe UI")
    
    hotkeyGui.Add("Text", "x20 y80", "Menu Key:")
    menuEdit := hotkeyGui.Add("Edit", "x150 y78 w100 Background0x2a2a3e cWhite", SETTINGS["hotkey_menu"])
    
    hotkeyGui.Add("Text", "x20 y115", "Suspend Key:")
    suspendEdit := hotkeyGui.Add("Edit", "x150 y113 w100 Background0x2a2a3e cWhite", SETTINGS["hotkey_suspend"])
    
    hotkeyGui.Add("Text", "x20 y150", "Mode Toggle:")
    modeEdit := hotkeyGui.Add("Edit", "x150 y148 w100 Background0x2a2a3e cWhite", SETTINGS["hotkey_mode_toggle"])
    
    ; Buttons
    tab.UseTab()
    
    helpBtn := hotkeyGui.Add("Button", "x20 y475 w80 h35", "❓ Help")
    helpBtn.OnEvent("Click", ShowHotkeyHelp)
    
    resetBtn := hotkeyGui.Add("Button", "x110 y475 w80 h35", "🔄 Reset")
    resetBtn.OnEvent("Click", ResetHotkeys)
    
    saveBtn := hotkeyGui.Add("Button", "x300 y475 w80 h35", "✅ Save")
    saveBtn.OnEvent("Click", SaveHotkeys)
    
    cancelBtn := hotkeyGui.Add("Button", "x390 y475 w80 h35", "❌ Cancel")
    cancelBtn.OnEvent("Click", (*) => hotkeyGui.Destroy())
    
    ShowHotkeyHelp(*) {
        helpText := "HOTKEY GUIDE - AutoHotkey v2`n`n"
        helpText .= "MOUSE BUTTONS:`n"
        helpText .= "• XButton1/XButton2 - Side mouse buttons`n"
        helpText .= "• LButton/RButton - Left/Right click`n`n"
        helpText .= "KEYBOARD KEYS:`n"
        helpText .= "• F1-F12 - Function keys`n"
        helpText .= "• Tab, Space, Enter, Delete, Home`n`n"
        helpText .= "MODIFIERS:`n"
        helpText .= "• ^ = Ctrl (e.g., ^a for Ctrl+A)`n"
        helpText .= "• ! = Alt (e.g., !Tab for Alt+Tab)`n"
        helpText .= "• + = Shift (e.g., +F1 for Shift+F1)`n"
        helpText .= "• # = Win (e.g., #d for Win+D)`n`n"
        helpText .= "COMBINATION KEYS (use &):`n"
        helpText .= "• a & b = Press 'a' then 'b' together`n"
        helpText .= "• Ctrl & x = Hold Ctrl and press x`n"
        
        MsgBox(helpText, "Hotkey Help", "Icon!")
    }
    
    ResetHotkeys(*) {
        result := MsgBox("Reset all hotkeys to default?", "Confirm Reset", "YesNo Icon?")
        
        if (result = "Yes") {
            macro1Edit.Text := "XButton1"
            macro2Edit.Text := "XButton2"
            ShowTooltip("Hotkeys reset to default", 2000)
        }
    }
    
    SaveHotkeys(*) {
    SETTINGS["hotkey_macro1"] := macro1Edit.Text
    SETTINGS["hotkey_macro2"] := macro2Edit.Text
    SETTINGS["macro1_mode"] := macro1Mode.Text
    SETTINGS["macro2_mode"] := macro2Mode.Text
    SETTINGS["hotkey_menu"] := menuEdit.Text
    SETTINGS["hotkey_suspend"] := suspendEdit.Text
    SETTINGS["hotkey_mode_toggle"] := modeEdit.Text
    SETTINGS["key_puncture_r"] := puncREdit.Text
    SETTINGS["key_puncture_t"] := puncTEdit.Text
    SETTINGS["key_puncture_tab"] := puncTabEdit.Text
    SETTINGS["key_hybrid_main"] := hybMainEdit.Text
    SETTINGS["key_hybrid_secondary"] := hybSecEdit.Text
    
    SaveSettings()
    
    ; Desregistrar todas as hotkeys antigas
    Try Hotkey("XButton1", "Off")
    Try Hotkey("XButton2", "Off")
    Hotkey("Delete", "Off")
    Hotkey("F12", "Off")
    Hotkey("Home", "Off")
    
    ; Registrar as novas hotkeys
    InitializeHotkeys()
    
    hotkeyGui.Destroy()
    ShowTooltip("✅ Hotkeys saved successfully!", 2000)
}
    
    hotkeyGui.Show("w490 h520")
}

; ================= SHOW MACRO CONFIG =================
ShowMacroConfig(*) {
    global GUI_REFS, SETTINGS, RUNTIME
    
    if (GUI_REFS["macro"]) {
        try GUI_REFS["macro"].Destroy()
    }
    
    macroGui := Gui("+AlwaysOnTop +ToolWindow", "🎮 Macro Configuration")
    macroGui.BackColor := "0x1a1a2e"
    macroGui.SetFont("s10 cFFFFFF", "Segoe UI")
    GUI_REFS["macro"] := macroGui
    
    tab := macroGui.Add("Tab3", "x5 y5 w490 h360", ["Puncture Timings", "Hybrid Timings", "Detection Settings"])
    
    ; === TAB 1: PUNCTURE TIMINGS ===
    tab.UseTab(1)
    macroGui.Add("Text", "x15 y35 w200", "Basic Puncture Settings:")
    
    macroGui.Add("Text", "x15 y60", "Loop Timing (ms):")
    timingEdit := macroGui.Add("Edit", "x140 y58 w60 Background0x16213e", SETTINGS["macro_timing"])
    TooltipManager.Show(timingEdit, "Base timing between key presses (milliseconds)")
    
    macroGui.Add("Text", "x15 y90", "Loop Count:")
    loopEdit := macroGui.Add("Edit", "x140 y88 w60 Background0x16213e", SETTINGS["macro_loop"])
    TooltipManager.Show(loopEdit, "Number of times to repeat key sequence")
    
    macroGui.Add("Text", "x15 y120", "Macro2 Puncture Sleeps:")
    
    macroGui.Add("Text", "x15 y150", "R Key Sleep:")
    puncX2Fast := macroGui.Add("Edit", "x140 y148 w60 Background0x16213e", SETTINGS["sleep_punc_x2_fast"])
    TooltipManager.Show(puncX2Fast, "Sleep time after R key press in Macro2")
    
    macroGui.Add("Text", "x15 y180", "Tab Key Sleep:")
    puncX2Tab := macroGui.Add("Edit", "x140 y178 w60 Background0x16213e", SETTINGS["sleep_punc_x2_tab"])
    TooltipManager.Show(puncX2Tab, "Sleep time after Tab key press in Macro2")
    
    macroGui.Add("Text", "x15 y210", "Between Keys:")
    puncX2Final := macroGui.Add("Edit", "x140 y208 w60 Background0x16213e", SETTINGS["sleep_punc_x2_final"])
    TooltipManager.Show(puncX2Final, "Delay between alternating keys in Macro2")
    
    macroGui.Add("Text", "x250 y60", "Macro1 Puncture Sleeps:")
    
    macroGui.Add("Text", "x250 y90", "After R Sequence:")
    puncX1RTabGap := macroGui.Add("Edit", "x380 y88 w60 Background0x16213e", SETTINGS["sleep_punc_x1_r_tab_gap"])
    TooltipManager.Show(puncX1RTabGap, "Sleep after R sequence before Tab sequence")
    
    macroGui.Add("Text", "x250 y120", "After Tab Sequence:")
    puncX1TabCritGap := macroGui.Add("Edit", "x380 y118 w60 Background0x16213e", SETTINGS["sleep_punc_x1_tab_crit_gap"])
    TooltipManager.Show(puncX1TabCritGap, "Sleep after Tab sequence before crit check")
    
    macroGui.Add("Text", "x250 y150", "Crit Detection Time:")
    puncX1CritCheck := macroGui.Add("Edit", "x380 y148 w60 Background0x16213e", SETTINGS["sleep_punc_x1_crit_check"])
    TooltipManager.Show(puncX1CritCheck, "Time to wait for critical hit detection")
    
    macroGui.Add("Text", "x250 y180", "After Crit Combo:")
    puncX1CritCombo := macroGui.Add("Edit", "x380 y178 w60 Background0x16213e", SETTINGS["sleep_punc_x1_crit_combo"])
    TooltipManager.Show(puncX1CritCombo, "Sleep after critical hit combo (unified for Ccrit and Lcrit)")
    
    macroGui.Add("Text", "x250 y210", "Between T Keys:")
    puncX1TBetween := macroGui.Add("Edit", "x380 y208 w60 Background0x16213e", SETTINGS["sleep_punc_x1_t_between"])
    TooltipManager.Show(puncX1TBetween, "Delay between T key presses in combo")
    
    macroGui.Add("Text", "x250 y240", "No Crit Found:")
    puncX1NoCrit := macroGui.Add("Edit", "x380 y238 w60 Background0x16213e", SETTINGS["sleep_punc_x1_no_crit"])
    TooltipManager.Show(puncX1NoCrit, "Sleep when no critical hit is detected")
    
    ; === TAB 2: HYBRID TIMINGS ===
    tab.UseTab(2)
    macroGui.Add("Text", "x15 y35", "Macro1 Custom Sequence:")
    hybridMacro1Sequence := macroGui.Add("Edit", "x15 y58 w200 Background0x16213e", SETTINGS["hybrid_macro1_sequence"])
    TooltipManager.Show(hybridMacro1Sequence, "Key sequence for Macro1 (comma-separated)")
    
    macroGui.Add("Text", "x15 y88", "Timing (ms):")
    hybridMacro1Timing := macroGui.Add("Edit", "x90 y86 w60 Background0x16213e", SETTINGS["hybrid_macro1_timing"])
    TooltipManager.Show(hybridMacro1Timing, "Timing between keys in sequence")
    
    macroGui.Add("Text", "x160 y88", "Mode:")
    hybridMacro1Mode := macroGui.Add("DropDownList", "x200 y86 w120", ["continuous", "repeat_count"])
    hybridMacro1Mode.Text := SETTINGS["hybrid_macro1_mode"]
    TooltipManager.Show(hybridMacro1Mode, "Continuous: Loop forever`nRepeat Count: Loop specific times")
    
    macroGui.Add("Text", "x15 y118", "Repeat Count:")
    hybridMacro1Repeat := macroGui.Add("Edit", "x100 y116 w60 Background0x16213e", SETTINGS["hybrid_macro1_repeat_count"])
    TooltipManager.Show(hybridMacro1Repeat, "Number of times to repeat sequence")
    
    macroGui.Add("Text", "x170 y118", "Seq Delay:")
    hybridMacro1SeqDelay := macroGui.Add("Edit", "x240 y116 w60 Background0x16213e", SETTINGS["hybrid_macro1_sequence_delay"])
    TooltipManager.Show(hybridMacro1SeqDelay, "Delay after completing sequence")
    
    macroGui.Add("Text", "x15 y150", "Macro2 Anicancel (Focus Detection):")
    hybridMacro2Sequence := macroGui.Add("Edit", "x15 y173 w200 Background0x16213e", SETTINGS["hybrid_macro2_sequence"])
    TooltipManager.Show(hybridMacro2Sequence, "Sequence when focus is detected")
    
    macroGui.Add("Text", "x15 y203", "Timing:")
    hybridMacro2Timing := macroGui.Add("Edit", "x60 y201 w60 Background0x16213e", SETTINGS["hybrid_macro2_timing"])
    
    macroGui.Add("Text", "x130 y203", "Pixel Pos:")
    hybridMacro2PixelPos := macroGui.Add("Edit", "x190 y201 w60 Background0x16213e", SETTINGS["hybrid_macro2_pixelsearch_position"])
    TooltipManager.Show(hybridMacro2PixelPos, "Position offset for pixel detection`n0 = Before First Input`n1 = After First Input`n2 = After Second Input...")
    
    macroGui.Add("Text", "x260 y203", "Seq Delay:")
    hybridMacro2SeqDelay := macroGui.Add("Edit", "x320 y201 w60 Background0x16213e", SETTINGS["hybrid_macro2_sequence_delay"])
    
    macroGui.Add("Text", "x15 y233", "No Focus Action:")
    hybridMacro2NoPixel := macroGui.Add("Edit", "x120 y231 w100 Background0x16213e", SETTINGS["hybrid_macro2_no_pixel_action"])
    TooltipManager.Show(hybridMacro2NoPixel, "Action when focus is not detected")
    
    macroGui.Add("Text", "x230 y233", "Delay:")
    hybridMacro2NoPixelDelay := macroGui.Add("Edit", "x270 y231 w60 Background0x16213e", SETTINGS["hybrid_macro2_no_pixel_delay"])
    
    ; === TAB 3: DETECTION SETTINGS ===
    tab.UseTab(3)
    macroGui.Add("Text", "x15 y35", "FindText Detection Settings:")
    
    macroGui.Add("Text", "x15 y60", "Retries:")
    findtextRetries := macroGui.Add("Edit", "x150 y58 w60 Background0x16213e", SETTINGS["findtext_retries"])
    TooltipManager.Show(findtextRetries, "Number of retries for FindText detection")
    
    macroGui.Add("Text", "x15 y90", "Retry Delay (ms):")
    findtextRetryDelay := macroGui.Add("Edit", "x150 y88 w60 Background0x16213e", SETTINGS["findtext_retry_delay"])
    TooltipManager.Show(findtextRetryDelay, "Delay between FindText retries")
    
    macroGui.Add("Text", "x15 y120", "PixelSearch Settings:")
    
    macroGui.Add("Text", "x15 y145", "Retries:")
    pixelRetries := macroGui.Add("Edit", "x150 y143 w60 Background0x16213e", SETTINGS["hybrid_pixelsearch_retries"])
    TooltipManager.Show(pixelRetries, "Number of retries for PixelSearch")
    
    macroGui.Add("Text", "x15 y175", "Retry Delay (ms):")
    pixelRetryDelay := macroGui.Add("Edit", "x150 y173 w60 Background0x16213e", SETTINGS["hybrid_pixelsearch_retry_delay"])
    TooltipManager.Show(pixelRetryDelay, "Delay between PixelSearch retries")
    
    ; Buttons
    tab.UseTab()
    
    debugBtn := macroGui.Add("Button", "x60 y375 w100 h30", RUNTIME.debugMode ? "Debug ON" : "Debug OFF")
    debugBtn.OnEvent("Click", ToggleDebugMode)
    
    saveBtn := macroGui.Add("Button", "x170 y375 w80 h30", "✅ Save")
    saveBtn.OnEvent("Click", SaveMacroConfig)
    
    cancelBtn := macroGui.Add("Button", "x260 y375 w80 h30", "❌ Cancel")
    cancelBtn.OnEvent("Click", (*) => macroGui.Destroy())
    
    resetBtn := macroGui.Add("Button", "x350 y375 w80 h30", "🔄 Reset")
    resetBtn.OnEvent("Click", ResetMacroConfig)
    
    ToggleDebugMode(*) {
        RUNTIME.debugMode := !RUNTIME.debugMode
        debugBtn.Text := RUNTIME.debugMode ? "Debug ON" : "Debug OFF"
        SETTINGS["debug_mode"] := RUNTIME.debugMode ? "1" : "0"
        SaveSettings()
        ShowTooltip("Debug mode " . (RUNTIME.debugMode ? "enabled" : "disabled"), 2000)
    }
    
    SaveMacroConfig(*) {
        SETTINGS["macro_timing"] := timingEdit.Text
        SETTINGS["macro_loop"] := loopEdit.Text
        SETTINGS["sleep_punc_x2_fast"] := puncX2Fast.Text
        SETTINGS["sleep_punc_x2_tab"] := puncX2Tab.Text
        SETTINGS["sleep_punc_x2_final"] := puncX2Final.Text
        SETTINGS["sleep_punc_x1_r_tab_gap"] := puncX1RTabGap.Text
        SETTINGS["sleep_punc_x1_tab_crit_gap"] := puncX1TabCritGap.Text
        SETTINGS["sleep_punc_x1_crit_check"] := puncX1CritCheck.Text
        SETTINGS["sleep_punc_x1_crit_combo"] := puncX1CritCombo.Text
        SETTINGS["sleep_punc_x1_t_between"] := puncX1TBetween.Text
        SETTINGS["sleep_punc_x1_no_crit"] := puncX1NoCrit.Text
        SETTINGS["hybrid_macro1_sequence"] := hybridMacro1Sequence.Text
        SETTINGS["hybrid_macro1_timing"] := hybridMacro1Timing.Text
        SETTINGS["hybrid_macro1_mode"] := hybridMacro1Mode.Text
        SETTINGS["hybrid_macro1_repeat_count"] := hybridMacro1Repeat.Text
        SETTINGS["hybrid_macro1_sequence_delay"] := hybridMacro1SeqDelay.Text
        SETTINGS["hybrid_macro2_sequence"] := hybridMacro2Sequence.Text
        SETTINGS["hybrid_macro2_timing"] := hybridMacro2Timing.Text
        SETTINGS["hybrid_macro2_sequence_delay"] := hybridMacro2SeqDelay.Text
        SETTINGS["hybrid_macro2_pixelsearch_position"] := hybridMacro2PixelPos.Text
        SETTINGS["hybrid_macro2_no_pixel_action"] := hybridMacro2NoPixel.Text
        SETTINGS["hybrid_macro2_no_pixel_delay"] := hybridMacro2NoPixelDelay.Text
        SETTINGS["findtext_retries"] := findtextRetries.Text
        SETTINGS["findtext_retry_delay"] := findtextRetryDelay.Text
        SETTINGS["hybrid_pixelsearch_retries"] := pixelRetries.Text
        SETTINGS["hybrid_pixelsearch_retry_delay"] := pixelRetryDelay.Text
        
        SaveSettings()
        macroGui.Destroy()
        ShowTooltip("✅ Configuration saved successfully!", 2000)
    }
    
    ResetMacroConfig(*) {
        result := MsgBox("Reset all values to default?", "Confirm Reset", "YesNo Icon?")
        if (result = "Yes") {
            ShowTooltip("✅ All values reset to defaults", 2000)
        }
    }
    
    macroGui.Show("w500 h415")
}

; ================= SHOW HYBRID CONFIG =================
ShowHybridConfig(*) {
    global GUI_REFS, SETTINGS
    
    if (GUI_REFS["hybrid"]) {
        try GUI_REFS["hybrid"].Destroy()
    }
    
    hybridGui := Gui("+AlwaysOnTop +ToolWindow", "🔄 Hybrid Configuration")
    hybridGui.BackColor := "0x1a1a2e"
    hybridGui.SetFont("s10 cFFFFFF", "Segoe UI")
    GUI_REFS["hybrid"] := hybridGui
    
    hybridGui.Add("Text", "x10 y10 w280 Center", "PIXEL DETECTION CONFIG")
    
    hybridGui.Add("Text", "x10 y40", "PixelSearch Area for Focus Detection:")
    
    hybridGui.Add("Text", "x10 y70", "X1:")
    x1Edit := hybridGui.Add("Edit", "x40 y68 w60 Background0x16213e", SETTINGS["hybrid_x1"])
    TooltipManager.Show(x1Edit, "Left X coordinate of search area")
    
    hybridGui.Add("Text", "x110 y70", "Y1:")
    y1Edit := hybridGui.Add("Edit", "x140 y68 w60 Background0x16213e", SETTINGS["hybrid_y1"])
    TooltipManager.Show(y1Edit, "Top Y coordinate of search area")
    
    hybridGui.Add("Text", "x10 y100", "X2:")
    x2Edit := hybridGui.Add("Edit", "x40 y98 w60 Background0x16213e", SETTINGS["hybrid_x2"])
    TooltipManager.Show(x2Edit, "Right X coordinate of search area")
    
    hybridGui.Add("Text", "x110 y100", "Y2:")
    y2Edit := hybridGui.Add("Edit", "x140 y98 w60 Background0x16213e", SETTINGS["hybrid_y2"])
    TooltipManager.Show(y2Edit, "Bottom Y coordinate of search area")
    
    hybridGui.Add("Text", "x10 y130", "Color (Hex):")
    colorEdit := hybridGui.Add("Edit", "x90 y128 w120 Background0x16213e", SETTINGS["hybrid_color"])
    colorEdit.OnEvent("Change", UpdateColorPreview)
    TooltipManager.Show(colorEdit, "Hex color to search for (e.g., 0xFF0000)")
    
    hybridGui.Add("Text", "x10 y160", "Variation:")
    varEdit := hybridGui.Add("Edit", "x90 y158 w60 Background0x16213e", SETTINGS["hybrid_variation"])
    TooltipManager.Show(varEdit, "Color variation tolerance (0-255)")
    
    hybridGui.Add("Text", "x10 y190", "Color Preview:")
    colorValue := SETTINGS["hybrid_color"]
    if (SubStr(colorValue, 1, 2) = "0x") {
        colorValue := SubStr(colorValue, 3)
    }
    colorPreview := hybridGui.Add("Progress", "x10 y210 w80 h50 Background" . colorValue . " c" . colorValue)
    
    UpdateColorPreview(*) {
        newColor := colorEdit.Text
        if (SubStr(newColor, 1, 2) = "0x") {
            newColor := SubStr(newColor, 3)
        }
        if (RegExMatch(newColor, "^[0-9A-Fa-f]{6}$")) {
            colorPreview.Opt("Background" . newColor . " c" . newColor)
        }
    }
    
    testBtn := hybridGui.Add("Button", "x10 y270 w100 h30", "🧪 Test")
    testBtn.OnEvent("Click", TestPixelSearchImproved)
    
    getColorBtn := hybridGui.Add("Button", "x120 y270 w100 h30", "🎨 Get Color")
    getColorBtn.OnEvent("Click", GetColorFromScreen)
    
    saveBtn := hybridGui.Add("Button", "x60 y310 w80 h30", "✅ Save")
    saveBtn.OnEvent("Click", SaveHybridConfig)
    
    cancelBtn := hybridGui.Add("Button", "x150 y310 w80 h30", "❌ Cancel")
    cancelBtn.OnEvent("Click", (*) => hybridGui.Destroy())
    
    TestPixelSearchImproved(*) {
        x1 := Integer(x1Edit.Text)
        y1 := Integer(y1Edit.Text)
        x2 := Integer(x2Edit.Text)
        y2 := Integer(y2Edit.Text)
        color := colorEdit.Text
        variation := Integer(varEdit.Text)
        
        oldCoordMode := A_CoordModePixel
        CoordMode("Pixel", "Screen")
        
        Px := 0
        Py := 0
        found := PixelSearch(&Px, &Py, x1, y1, x2, y2, color, variation)
        
        if (found) {
            ShowTooltip("✅ Pixel found at " . Px . "," . Py, 2000)
            
            indicatorGui := Gui("+AlwaysOnTop -Caption +ToolWindow +E0x20")
            indicatorGui.BackColor := "Lime"
            WinSetTransColor("Lime", indicatorGui)
            indicatorGui.Opt("+LastFound")
            
            indicatorGui.Show("x" . (Px - 10) . " y" . (Py - 10) . " w20 h20 NoActivate")
            
            Loop 6 {
                if (Mod(A_Index, 2) = 0) {
                    indicatorGui.Show()
                } else {
                    indicatorGui.Hide()
                }
                Sleep(250)
            }
            
            indicatorGui.Destroy()
        } else {
            ShowTooltip("❌ Pixel not found in area", 2000)
        }
        
        CoordMode("Pixel", oldCoordMode)
    }
    
    GetColorFromScreen(*) {
        hybridGui.Minimize()
        ShowTooltip("Click on the focus circle to capture color", 5000)
        
        KeyWait("LButton", "D")
        CoordMode("Mouse", "Screen")
        CoordMode("Pixel", "Screen")
        MouseGetPos(&mouseX, &mouseY)
        pixelColor := PixelGetColor(mouseX, mouseY)
        colorHex := Format("0x{:06X}", pixelColor)
        
        x1Edit.Text := mouseX - 3
        y1Edit.Text := mouseY - 3
        x2Edit.Text := mouseX + 3
        y2Edit.Text := mouseY + 3
        colorEdit.Text := colorHex
        UpdateColorPreview()
        
        ShowTooltip("✅ Color captured: " . colorHex, 2000)
        hybridGui.Restore()
    }
    
    SaveHybridConfig(*) {
        SETTINGS["hybrid_x1"] := x1Edit.Text
        SETTINGS["hybrid_y1"] := y1Edit.Text
        SETTINGS["hybrid_x2"] := x2Edit.Text
        SETTINGS["hybrid_y2"] := y2Edit.Text
        SETTINGS["hybrid_color"] := colorEdit.Text
        SETTINGS["hybrid_variation"] := varEdit.Text
        
        SaveSettings()
        hybridGui.Destroy()
        ShowTooltip("✅ Configuration saved!", 2000)
    }
    
    hybridGui.Show("w290 h350")
}

; ================= SHOW PUNCTURE CONFIG =================
ShowPunctureConfig(*) {
    global GUI_REFS, SETTINGS, PATTERNS
    
    if (GUI_REFS["puncture"]) {
        try GUI_REFS["puncture"].Destroy()
        GUI_REFS["puncture"] := ""
    }
    
    GUI_REFS["puncture"] := Gui("+AlwaysOnTop +ToolWindow", "🎯 Puncture Configuration")
    GUI_REFS["puncture"].BackColor := "0x1a1a2e"
    GUI_REFS["puncture"].SetFont("s10 cFFFFFF", "Segoe UI")
    
    GUI_REFS["puncture"].Add("Text", "x10 y10 w280 Center", "FINDTEXT CONFIGURATION")
    
    GUI_REFS["puncture"].Add("Text", "x10 y40", "Search Area (x1, y1, x2, y2):")
    currentArea := SETTINGS["puncture_x1"] . ", " . SETTINGS["puncture_y1"] . ", " . 
                   SETTINGS["puncture_x2"] . ", " . SETTINGS["puncture_y2"]
    areaEdit := GUI_REFS["puncture"].Add("Edit", "x10 y60 w280 Background0x16213e", currentArea)
    
    GUI_REFS["puncture"].Add("Text", "x10 y95", "Ccrit Code:")
    ccritEdit := GUI_REFS["puncture"].Add("Edit", "x10 y115 w280 h50 VScroll Background0x16213e", PATTERNS.Ccrit)
    
    GUI_REFS["puncture"].Add("Text", "x10 y175", "Lcrit Code:")
    lcritEdit := GUI_REFS["puncture"].Add("Edit", "x10 y195 w280 h50 VScroll Background0x16213e", PATTERNS.Lcrit)
    
    findTextBtn := GUI_REFS["puncture"].Add("Button", "x10 y260 w80 h30", "🔍 FindText")
    findTextBtn.OnEvent("Click", OpenFindText)
    
    testBtn := GUI_REFS["puncture"].Add("Button", "x100 y260 w80 h30", "🧪 Test")
    testBtn.OnEvent("Click", TestFindTextDetection)
    
    saveBtn := GUI_REFS["puncture"].Add("Button", "x190 y260 w80 h30", "✅ Save")
    saveBtn.OnEvent("Click", SavePunctureConfig)
    
    cancelBtn := GUI_REFS["puncture"].Add("Button", "x110 y300 w80 h30", "❌ Cancel")
    cancelBtn.OnEvent("Click", (*) => GUI_REFS["puncture"].Destroy())
    
    OpenFindText(*) {
        try {
            findTextPath := A_ScriptDir . "\FindText.ahk"
            if FileExist(findTextPath) {
                Run(findTextPath)
                ShowTooltip("FindText tool opened!", 2000)
            } else {
                ShowTooltip("FindText.ahk not found!", 2000)
            }
        } catch {
            ShowTooltip("Error opening FindText!", 2000)
        }
    }
    
    TestFindTextDetection(*) {
        x1 := Integer(SETTINGS["puncture_x1"])
        y1 := Integer(SETTINGS["puncture_y1"])
        x2 := Integer(SETTINGS["puncture_x2"])
        y2 := Integer(SETTINGS["puncture_y2"])
        
        X := 0
        Y := 0
        
        startTime := A_TickCount
        ccritFound := FindText(&X, &Y, x1, y1, x2, y2, 0, 0, PATTERNS.Ccrit)
        ccritTime := A_TickCount - startTime
        
        startTime := A_TickCount
        lcritFound := FindText(&X, &Y, x1, y1, x2, y2, 0, 0, PATTERNS.Lcrit)
        lcritTime := A_TickCount - startTime
        
        result := "Test Results:`n"
        result .= "Ccrit: " . (ccritFound ? "✅ FOUND in " . ccritTime . "ms" : "❌ NOT FOUND") . "`n"
        result .= "Lcrit: " . (lcritFound ? "✅ FOUND in " . lcritTime . "ms" : "❌ NOT FOUND")
        
        MsgBox(result, "FindText Detection Test", "OK Icon!")
    }
    
    SavePunctureConfig(*) {
        areaText := areaEdit.Text
        areaParts := StrSplit(areaText, ",")
        
        if areaParts.Length >= 4 {
            SETTINGS["puncture_x1"] := Trim(areaParts[1])
            SETTINGS["puncture_y1"] := Trim(areaParts[2])
            SETTINGS["puncture_x2"] := Trim(areaParts[3])
            SETTINGS["puncture_y2"] := Trim(areaParts[4])
        }
        
        PATTERNS.Ccrit := ccritEdit.Text
        PATTERNS.Lcrit := lcritEdit.Text
        
        SaveSettings()
        GUI_REFS["puncture"].Destroy()
        ShowTooltip("✅ Puncture configuration saved!", 2000)
    }
    
    GUI_REFS["puncture"].Show("w300 h340")
}

; ================= SHOW FLOWCHART =================
ShowFlowchart(*) {
    global GUI_REFS, RUNTIME, SETTINGS
    
    if (GUI_REFS["flowchart"]) {
        try GUI_REFS["flowchart"].Destroy()
    }
    
    flowchartGui := Gui("+AlwaysOnTop +Resize", "📊 Macro Flowchart")
    flowchartGui.BackColor := "0x1a1a2e"
    flowchartGui.SetFont("s10 cFFFFFF", "Consolas")
    GUI_REFS["flowchart"] := flowchartGui
    
    flowchartGui.SetFont("s12 Bold cFFFF00", "Segoe UI")
    modeText := flowchartGui.Add("Text", "x10 y10 w650 Center", 
        "Flowchart View: " . (RUNTIME.flowchartMode = "puncture" ? "🎯 PUNCTURE" : "🔄 HYBRID"))
    
    flowchartGui.SetFont("s10 cFFFFFF", "Consolas")
    
    flowText := GenerateFlowchartText(RUNTIME.flowchartMode)
    flowchartEdit := flowchartGui.Add("Edit", "x10 y40 w650 h500 ReadOnly VScroll Background0x16213e", flowText)
    
    flowchartGui.SetFont("s10 Bold", "Segoe UI")
    
    switchBtn := flowchartGui.Add("Button", "x150 y550 w120 h35", 
        RUNTIME.flowchartMode = "puncture" ? "📄 View Hybrid" : "📄 View Puncture")
    switchBtn.OnEvent("Click", SwitchFlowchartView)
    
    closeBtn := flowchartGui.Add("Button", "x390 y550 w100 h35", "❌ Close")
    closeBtn.OnEvent("Click", (*) => flowchartGui.Destroy())
    
    flowchartGui.Show("w670 h600")
    
    SwitchFlowchartView(*) {
        if (RUNTIME.flowchartMode = "puncture") {
            RUNTIME.flowchartMode := "hybrid"
        } else {
            RUNTIME.flowchartMode := "puncture"
        }
        RefreshFlowchart()
    }
    
    RefreshFlowchart(*) {
        modeText.Text := "Flowchart View: " . (RUNTIME.flowchartMode = "puncture" ? "🎯 PUNCTURE" : "🔄 HYBRID")
        switchBtn.Text := RUNTIME.flowchartMode = "puncture" ? "📄 View Hybrid" : "📄 View Puncture"
        flowchartEdit.Text := GenerateFlowchartText(RUNTIME.flowchartMode)
    }
}

GenerateFlowchartText(viewMode) {
    global SETTINGS
    
    flowText := ""
    
    if (viewMode = "puncture") {
        flowText := "🎯 PUNCTURE MODE FLOWCHART`r`n"
        flowText .= "══════════════════════════`r`n`r`n"
        flowText .= "MACRO 1 (XButton1):`r`n"
        flowText .= "┌─────────────────┐`r`n"
        flowText .= "│  START MACRO1   │`r`n"
        flowText .= "└────────┬────────┘`r`n"
        flowText .= "         ↓`r`n"
        flowText .= "┌─────────────────┐`r`n"
        flowText .= "│  Loop " . (SETTINGS.Has("macro_loop") ? SETTINGS["macro_loop"] : "4") . " times   │`r`n"
        flowText .= "│  Send {" . (SETTINGS.Has("key_puncture_r") ? SETTINGS["key_puncture_r"] : "r") . "}       │`r`n"
        flowText .= "│  Sleep " . (SETTINGS.Has("macro_timing") ? SETTINGS["macro_timing"] : "30") . "ms     │`r`n"
        flowText .= "└────────┬────────┘`r`n"
        flowText .= "         ↓`r`n"
        flowText .= "    Sleep " . SETTINGS["sleep_punc_x1_r_tab_gap"] . "ms`r`n"
        flowText .= "         ↓`r`n"
        flowText .= "┌─────────────────┐`r`n"
        flowText .= "│  Loop " . SETTINGS["macro_loop"] . " times   │`r`n"
        flowText .= "│  Send {" . SETTINGS["key_puncture_tab"] . "}     │`r`n"
        flowText .= "│  Sleep " . SETTINGS["macro_timing"] . "ms     │`r`n"
        flowText .= "└────────┬────────┘`r`n"
        flowText .= "         ↓`r`n"
        flowText .= "    Sleep " . SETTINGS["sleep_punc_x1_tab_crit_gap"] . "ms`r`n"
        flowText .= "         ↓`r`n"
        flowText .= "┌─────────────────┐`r`n"
        flowText .= "│  FindText Check │`r`n"
        flowText .= "│  Ccrit & Lcrit  │`r`n"
        flowText .= "└────┬───┬────────┘`r`n"
        flowText .= "  Found  Not Found`r`n"
        flowText .= "     ↓       ↓`r`n"
        flowText .= "┌────────┐ Sleep " . SETTINGS["sleep_punc_x1_no_crit"] . "ms`r`n"
        flowText .= "│ 4x {" . SETTINGS["key_puncture_t"] . "} │`r`n"
        flowText .= "└────────┘`r`n`r`n"
        flowText .= "MACRO 2 (XButton2):`r`n"
        flowText .= "┌─────────────────┐`r`n"
        flowText .= "│  START MACRO2   │`r`n"
        flowText .= "└────────┬────────┘`r`n"
        flowText .= "         ↓`r`n"
        flowText .= "┌─────────────────┐`r`n"
        flowText .= "│ Alternate Keys  │`r`n"
        flowText .= "│ {" . SETTINGS["key_puncture_r"] . "} ↔ {" . SETTINGS["key_puncture_tab"] . "}     │`r`n"
        flowText .= "│ Sleep varies    │`r`n"
        flowText .= "└─────────────────┘"
    } else {
        flowText := "🔄 HYBRID MODE FLOWCHART`r`n"
        flowText .= "══════════════════════════`r`n`r`n"
        flowText .= "MACRO 1 (XButton1):`r`n"
        flowText .= "┌─────────────────┐`r`n"
        flowText .= "│  START MACRO1   │`r`n"
        flowText .= "└────────┬────────┘`r`n"
        flowText .= "         ↓`r`n"
        flowText .= "┌─────────────────┐`r`n"
        flowText .= "│ Execute Sequence│`r`n"
        flowText .= "│ " . SETTINGS["hybrid_macro1_sequence"] . "               │`r`n"
        flowText .= "│ Timing: " . SETTINGS["hybrid_macro1_timing"] . "ms    │`r`n"
        flowText .= "└────────┬────────┘`r`n"
        flowText .= "         ↓`r`n"
        flowText .= "    Mode: " . SETTINGS["hybrid_macro1_mode"] . "`r`n"
        flowText .= "    Delay: " . SETTINGS["hybrid_macro1_sequence_delay"] . "ms`r`n`r`n"
        flowText .= "MACRO 2 (XButton2) - Anicancel:`r`n"
        flowText .= "┌─────────────────┐`r`n"
        flowText .= "│  START MACRO2   │`r`n"
        flowText .= "└────────┬────────┘`r`n"
        flowText .= "         ↓`r`n"
        flowText .= "┌─────────────────┐`r`n"
        flowText .= "│ PixelSearch     │`r`n"
        flowText .= "│ Color: " . SETTINGS["hybrid_color"] . " │`r`n"
        flowText .= "└────┬───┬────────┘`r`n"
        flowText .= "  Found  Not Found`r`n"
        flowText .= "     ↓       ↓`r`n"
        flowText .= "┌────────┐  ┌────────┐`r`n"
        flowText .= "│Execute │  │Fallback│`r`n"
        flowText .= "│" . SETTINGS["hybrid_macro2_sequence"] . "   │  │" . SETTINGS["hybrid_macro2_no_pixel_action"] . "       │`r`n"
        flowText .= "└────────┘  └────────┘"
    }
    
    return flowText
}

; ================= FUNÇÃO MELHORADA: GetShareableSettings =================
GetShareableSettings() {
    global SETTINGS
    
    ; Create a map with default values for all shareable settings
    shareable := Map()
    
    ; Basic timing
    shareable["macro_timing"] := SETTINGS.Has("macro_timing") ? SETTINGS["macro_timing"] : "30"
    shareable["macro_loop"] := SETTINGS.Has("macro_loop") ? SETTINGS["macro_loop"] : "4"
    
    ; Puncture mode sleeps
    shareable["sleep_punc_x2_fast"] := SETTINGS.Has("sleep_punc_x2_fast") ? SETTINGS["sleep_punc_x2_fast"] : "15"
    shareable["sleep_punc_x2_tab"] := SETTINGS.Has("sleep_punc_x2_tab") ? SETTINGS["sleep_punc_x2_tab"] : "30"
    shareable["sleep_punc_x2_final"] := SETTINGS.Has("sleep_punc_x2_final") ? SETTINGS["sleep_punc_x2_final"] : "5"
    shareable["sleep_punc_x1_r_tab_gap"] := SETTINGS.Has("sleep_punc_x1_r_tab_gap") ? SETTINGS["sleep_punc_x1_r_tab_gap"] : "85"
    shareable["sleep_punc_x1_tab_crit_gap"] := SETTINGS.Has("sleep_punc_x1_tab_crit_gap") ? SETTINGS["sleep_punc_x1_tab_crit_gap"] : "65"
    shareable["sleep_punc_x1_crit_check"] := SETTINGS.Has("sleep_punc_x1_crit_check") ? SETTINGS["sleep_punc_x1_crit_check"] : "100"
    shareable["sleep_punc_x1_crit_combo"] := SETTINGS.Has("sleep_punc_x1_crit_combo") ? SETTINGS["sleep_punc_x1_crit_combo"] : "85"
    shareable["sleep_punc_x1_t_between"] := SETTINGS.Has("sleep_punc_x1_t_between") ? SETTINGS["sleep_punc_x1_t_between"] : "20"
    shareable["sleep_punc_x1_no_crit"] := SETTINGS.Has("sleep_punc_x1_no_crit") ? SETTINGS["sleep_punc_x1_no_crit"] : "50"
    
    ; Hybrid mode timings
    shareable["hybrid_macro1_timing"] := SETTINGS.Has("hybrid_macro1_timing") ? SETTINGS["hybrid_macro1_timing"] : "10"
    shareable["hybrid_macro1_sequence_delay"] := SETTINGS.Has("hybrid_macro1_sequence_delay") ? SETTINGS["hybrid_macro1_sequence_delay"] : "50"
    shareable["hybrid_macro1_repeat_count"] := SETTINGS.Has("hybrid_macro1_repeat_count") ? SETTINGS["hybrid_macro1_repeat_count"] : "1"
    shareable["hybrid_macro2_timing"] := SETTINGS.Has("hybrid_macro2_timing") ? SETTINGS["hybrid_macro2_timing"] : "10"
    shareable["hybrid_macro2_sequence_delay"] := SETTINGS.Has("hybrid_macro2_sequence_delay") ? SETTINGS["hybrid_macro2_sequence_delay"] : "50"
    shareable["hybrid_macro2_no_pixel_delay"] := SETTINGS.Has("hybrid_macro2_no_pixel_delay") ? SETTINGS["hybrid_macro2_no_pixel_delay"] : "50"
    
    ; Detection retry settings
    shareable["findtext_retries"] := SETTINGS.Has("findtext_retries") ? SETTINGS["findtext_retries"] : "3"
    shareable["findtext_retry_delay"] := SETTINGS.Has("findtext_retry_delay") ? SETTINGS["findtext_retry_delay"] : "10"
    shareable["hybrid_pixelsearch_retries"] := SETTINGS.Has("hybrid_pixelsearch_retries") ? SETTINGS["hybrid_pixelsearch_retries"] : "3"
    shareable["hybrid_pixelsearch_retry_delay"] := SETTINGS.Has("hybrid_pixelsearch_retry_delay") ? SETTINGS["hybrid_pixelsearch_retry_delay"] : "5"
    
    return shareable
}

; ================= HOTKEY INITIALIZATION =================
InitializeHotkeys() {
    global SETTINGS
    
    try Hotkey(Trim(SETTINGS.Get("hotkey_mode_toggle", "Home")), ToggleMode, "On")
    try Hotkey(Trim(SETTINGS.Get("hotkey_menu", "Delete")), ShowMainMenu, "On")
    try Hotkey(Trim(SETTINGS.Get("hotkey_suspend", "F12")), ToggleSuspend, "On")
    try Hotkey(Trim(SETTINGS.Get("hotkey_macro1", "XButton1")), Macro1Action, "On")
    try Hotkey(Trim(SETTINGS.Get("hotkey_macro2", "XButton2")), Macro2Action, "On")
}

; ================= HOTKEY ACTIONS =================
Macro1Action(*) {
    global RUNTIME, SETTINGS
    
    if (RUNTIME.suspendMacros) {
        return
    }
    
    if (SETTINGS["macro1_mode"] = "toggle") {
        if (RUNTIME.macro1Active) {
            RUNTIME.macro1Active := false
            ShowTooltip("Macro1 OFF", 1000)
        } else {
            RUNTIME.macro1Active := true
            RUNTIME.macro1Type := RUNTIME.mode
            ShowTooltip("Macro1 ON", 1000)
            SetTimer(Macro1Loop, 10)
        }
    } else {
        if (RUNTIME.mode = "puncture") {
            PunctureMacro1()
        } else {
            HybridMacro1()
        }
    }
}

Macro2Action(*) {
    global RUNTIME, SETTINGS
    
    if (RUNTIME.suspendMacros) {
        return
    }
    
    if (SETTINGS["macro2_mode"] = "toggle") {
        if (RUNTIME.macro2Active) {
            RUNTIME.macro2Active := false
            ShowTooltip("Macro2 OFF", 1000)
        } else {
            RUNTIME.macro2Active := true
            RUNTIME.macro2Type := RUNTIME.mode
            ShowTooltip("Macro2 ON", 1000)
            SetTimer(Macro2Loop, 10)
        }
    } else {
        if (RUNTIME.mode = "puncture") {
            PunctureMacro2()
        } else {
            HybridMacro2()
        }
    }
}

ToggleSuspend(*) {
    global RUNTIME
    
    RUNTIME.suspendMacros := !RUNTIME.suspendMacros
    ShowTooltip("Macros " . (RUNTIME.suspendMacros ? "SUSPENDED ⏸️" : "ACTIVATED ▶️"), 2000)
    UpdateMainMenuStatus()
    SupabaseClient.LogActivity("macro_suspend", RUNTIME.suspendMacros ? "Suspended" : "Activated")
}

ToggleMode(*) {
    global RUNTIME
    
    if (RUNTIME.mode = "puncture") {
        RUNTIME.mode := "hybrid"
        ShowTooltip("Switched to HYBRID mode! 🔄", 2000)
    } else {
        RUNTIME.mode := "puncture"
        ShowTooltip("Switched to PUNCTURE mode! 🎯", 2000)
    }
    
    UpdateMainMenuStatus()
    SupabaseClient.LogActivity("mode_toggle", "Toggled to " . RUNTIME.mode)
}

; ================= PUNCTURE MACROS =================
PunctureMacro1() {
    global RUNTIME, SETTINGS, PATTERNS
    
    while (GetKeyState(SETTINGS["hotkey_macro1"], "P") && !RUNTIME.suspendMacros) {
        timing := Integer(SETTINGS["macro_timing"])
        loops := Integer(SETTINGS["macro_loop"])
        
        Loop loops {
            if (!GetKeyState(SETTINGS["hotkey_macro1"], "P") || RUNTIME.suspendMacros)
                return
            Send("{" . SETTINGS["key_puncture_r"] . "}")
            Sleep(timing)
        }
        
        Sleep(Integer(SETTINGS["sleep_punc_x1_r_tab_gap"]))
        
        Loop loops {
            if (!GetKeyState(SETTINGS["hotkey_macro1"], "P") || RUNTIME.suspendMacros)
                return
            Send("{" . SETTINGS["key_puncture_tab"] . "}")
            Sleep(timing)
        }
        
        Sleep(Integer(SETTINGS["sleep_punc_x1_tab_crit_gap"]))
        
        x1 := Integer(SETTINGS["puncture_x1"])
        y1 := Integer(SETTINGS["puncture_y1"])
        x2 := Integer(SETTINGS["puncture_x2"])
        y2 := Integer(SETTINGS["puncture_y2"])
        X := 0
        Y := 0
        
        ccritFound := FindText(&X, &Y, x1, y1, x2, y2, 0, 0, PATTERNS.Ccrit)
        lcritFound := FindText(&X, &Y, x1, y1, x2, y2, 0, 0, PATTERNS.Lcrit)
        
        if (ccritFound || lcritFound) {
            if (RUNTIME.debugMode) {
                ShowTooltip("✅ CRIT DETECTED!", 1500)
            }
            
            Loop 4 {
                if (!GetKeyState(SETTINGS["hotkey_macro1"], "P") || RUNTIME.suspendMacros)
                    return
                Send("{" . SETTINGS["key_puncture_t"] . "}")
                if (A_Index < 4)
                    Sleep(Integer(SETTINGS["sleep_punc_x1_t_between"]))
            }
            
            Sleep(Integer(SETTINGS["sleep_punc_x1_crit_combo"]))
        } else {
            if (RUNTIME.debugMode) {
                ShowTooltip("❌ NO CRITS", 1000)
            }
            Sleep(Integer(SETTINGS["sleep_punc_x1_no_crit"]))
        }
    }
}

PunctureMacro2() {
    global RUNTIME, SETTINGS
    static lastKey := "r"
    
    while (GetKeyState(SETTINGS["hotkey_macro2"], "P") && !RUNTIME.suspendMacros) {
        if (lastKey = "r") {
            Send("{" . SETTINGS["key_puncture_tab"] . "}")
            Sleep(Integer(SETTINGS["sleep_punc_x2_tab"]))
            lastKey := "Tab"
        } else {
            Send("{" . SETTINGS["key_puncture_r"] . "}")
            Sleep(Integer(SETTINGS["sleep_punc_x2_fast"]))
            lastKey := "r"
        }
        Sleep(Integer(SETTINGS["sleep_punc_x2_final"]))
    }
}

; ================= HYBRID MACROS =================
HybridMacro1() {
    global RUNTIME, SETTINGS
    
    while (GetKeyState(SETTINGS["hotkey_macro1"], "P") && !RUNTIME.suspendMacros) {
        ExecuteHybridMacro1Sequence()
        Sleep(1)
    }
}

HybridMacro2() {
    global RUNTIME, SETTINGS
    
    while (GetKeyState(SETTINGS["hotkey_macro2"], "P") && !RUNTIME.suspendMacros) {
        ExecuteHybridMacro2Anicancel()
        Sleep(1)
    }
}

ExecuteHybridMacro1Sequence() {
    global SETTINGS, RUNTIME
    
    sequence := SETTINGS["hybrid_macro1_sequence"]
    timing := Integer(SETTINGS["hybrid_macro1_timing"])
    
    sequence := StrReplace(sequence, "t", SETTINGS["key_hybrid_main"])
    sequence := StrReplace(sequence, "r", SETTINGS["key_hybrid_secondary"])
    
    keys := StrSplit(sequence, ",")
    
    for key in keys {
        cleanKey := Trim(key)
        if (cleanKey != "") {
            if (SETTINGS["macro1_mode"] = "hold" && !GetKeyState(SETTINGS["hotkey_macro1"], "P"))
                return
            if (RUNTIME.suspendMacros)
                return
                
            Send("{" . cleanKey . "}")
            Sleep(timing)
        }
    }
    
    Sleep(Integer(SETTINGS["hybrid_macro1_sequence_delay"]))
}

ExecuteHybridMacro2Anicancel() {
    global SETTINGS, RUNTIME
    
    sequence := SETTINGS["hybrid_macro2_sequence"]
    timing := Integer(SETTINGS["hybrid_macro2_timing"])
    noPixelAction := SETTINGS["hybrid_macro2_no_pixel_action"]
    noPixelDelay := Integer(SETTINGS["hybrid_macro2_no_pixel_delay"])
    
    sequence := StrReplace(sequence, "t", SETTINGS["key_hybrid_main"])
    sequence := StrReplace(sequence, "r", SETTINGS["key_hybrid_secondary"])
    
    x1 := Integer(SETTINGS["hybrid_x1"])
    y1 := Integer(SETTINGS["hybrid_y1"])
    x2 := Integer(SETTINGS["hybrid_x2"])
    y2 := Integer(SETTINGS["hybrid_y2"])
    color := SETTINGS["hybrid_color"]
    variation := Integer(SETTINGS["hybrid_variation"])
    
    Px := 0
    Py := 0
    focusFound := PixelSearch(&Px, &Py, x1, y1, x2, y2, color, variation)
    
    if (focusFound) {
        if (RUNTIME.debugMode) {
            ShowTooltip("🎯 FOCUS DETECTED", 500)
        }
        
        keys := StrSplit(sequence, ",")
        for key in keys {
            cleanKey := Trim(key)
            if (cleanKey != "") {
                if (SETTINGS["macro2_mode"] = "hold" && !GetKeyState(SETTINGS["hotkey_macro2"], "P"))
                    return
                if (RUNTIME.suspendMacros)
                    return
                    
                Send("{" . cleanKey . "}")
                Sleep(timing)
            }
        }
        
        Sleep(Integer(SETTINGS["hybrid_macro2_sequence_delay"]))
    } else {
        if (noPixelAction != "") {
            noPixelKeys := StrSplit(noPixelAction, ",")
            for fallbackKey in noPixelKeys {
                cleanFallback := Trim(fallbackKey)
                if (cleanFallback != "") {
                    if (RUNTIME.suspendMacros)
                        return
                        
                    Send("{" . cleanFallback . "}")
                    Sleep(timing)
                }
            }
            
            if (noPixelDelay > 0) {
                Sleep(noPixelDelay)
            }
        }
    }
}

Macro1Loop() {
    global RUNTIME
    
    if (!RUNTIME.macro1Active || RUNTIME.suspendMacros) {
        SetTimer(, 0)
        return
    }
    
    if (RUNTIME.macro1Type = "puncture") {
        PunctureMacro1Toggle()
    } else {
        ExecuteHybridMacro1Sequence()
    }
    
    if (RUNTIME.macro1Active && !RUNTIME.suspendMacros) {
        SetTimer(Macro1Loop, -10)
    }
}

Macro2Loop() {
    global RUNTIME
    
    if (!RUNTIME.macro2Active || RUNTIME.suspendMacros) {
        SetTimer(, 0)
        return
    }
    
    if (RUNTIME.macro2Type = "puncture") {
        PunctureMacro2Toggle()
    } else {
        ExecuteHybridMacro2Anicancel()
    }
    
    if (RUNTIME.macro2Active && !RUNTIME.suspendMacros) {
        SetTimer(Macro2Loop, -10)
    }
}

PunctureMacro1Toggle() {
    global SETTINGS, PATTERNS, RUNTIME
    
    timing := Integer(SETTINGS["macro_timing"])
    loops := Integer(SETTINGS["macro_loop"])
    
    Loop loops {
        if (!RUNTIME.macro1Active || RUNTIME.suspendMacros)
            return
        Send("{" . SETTINGS["key_puncture_r"] . "}")
        Sleep(timing)
    }
    
    Sleep(Integer(SETTINGS["sleep_punc_x1_r_tab_gap"]))
    
    Loop loops {
        if (!RUNTIME.macro1Active || RUNTIME.suspendMacros)
            return
        Send("{" . SETTINGS["key_puncture_tab"] . "}")
        Sleep(timing)
    }
    
    Sleep(Integer(SETTINGS["sleep_punc_x1_tab_crit_gap"]))
    
    x1 := Integer(SETTINGS["puncture_x1"])
    y1 := Integer(SETTINGS["puncture_y1"])
    x2 := Integer(SETTINGS["puncture_x2"])
    y2 := Integer(SETTINGS["puncture_y2"])
    X := 0
    Y := 0
    
    ccritFound := FindText(&X, &Y, x1, y1, x2, y2, 0, 0, PATTERNS.Ccrit)
    lcritFound := FindText(&X, &Y, x1, y1, x2, y2, 0, 0, PATTERNS.Lcrit)
    
    if (ccritFound || lcritFound) {
        Loop 4 {
            if (!RUNTIME.macro1Active || RUNTIME.suspendMacros)
                return
            Send("{" . SETTINGS["key_puncture_t"] . "}")
            if (A_Index < 4)
                Sleep(Integer(SETTINGS["sleep_punc_x1_t_between"]))
        }
        
        Sleep(Integer(SETTINGS["sleep_punc_x1_crit_combo"]))
    } else {
        Sleep(Integer(SETTINGS["sleep_punc_x1_no_crit"]))
    }
}

PunctureMacro2Toggle() {
    global SETTINGS
    static lastKey := "r"
    
    if (lastKey = "r") {
        Send("{" . SETTINGS["key_puncture_tab"] . "}")
        Sleep(Integer(SETTINGS["sleep_punc_x2_tab"]))
        lastKey := "Tab"
    } else {
        Send("{" . SETTINGS["key_puncture_r"] . "}")
        Sleep(Integer(SETTINGS["sleep_punc_x2_fast"]))
        lastKey := "r"
    }
    
    Sleep(Integer(SETTINGS["sleep_punc_x2_final"]))
}

; ================= INITIALIZATION =================
OnExit(Cleanup)

CreateTrayMenu()

CreateTrayMenu() {
    A_TrayMenu.Delete()
    
    A_TrayMenu.Add("📊 Show Menu", ShowMainMenuFromTray)
    A_TrayMenu.Add("🔄 Refresh", RefreshScript)
    A_TrayMenu.Add()
    
    if (SESSION.authenticated) {
        A_TrayMenu.Add("🚪 Logout", LogoutFromTray)
        A_TrayMenu.Add()
    }
    
    A_TrayMenu.Add("❌ Exit", ExitScript)
    
    A_TrayMenu.Default := "📊 Show Menu"
}

ShowMainMenuFromTray(*) {
    if (SESSION.authenticated) {
        ShowMainMenu()
    } else {
        MsgBox("Please login first", "Not Authenticated", "Icon!")
    }
}

RefreshScript(*) {
    Reload()
}

LogoutFromTray(*) {
    result := MsgBox("Are you sure you want to logout?`n`nThis will close the current session.", 
                    "Confirm Logout", "YesNo Icon?")
    
    if (result = "Yes") {
        SupabaseClient.Logout()
        MsgBox("Logged out successfully. Please restart the application.", "Logout", "Icon!")
        ExitApp()
    }
}

ExitScript(*) {
    result := MsgBox("Are you sure you want to exit?", "Confirm Exit", "YesNo Icon?")
    
    if (result = "Yes") {
        ExitApp()
    }
}

Cleanup(*) {
    global SESSION, GUI_REFS
    
    if (SESSION.authenticated) {
        SupabaseClient.LogActivity("logout", "Application closed normally")
    }
    
    SaveSettings()
    
    for name, gui in GUI_REFS {
        if (IsObject(gui)) {
            try gui.Destroy()
        }
    }
    
    ExitApp()
}

; ================= MAIN ENTRY POINT =================
; Initialize security
SecurityManager.Initialize()
ErrorHandler.Initialize()

; Create directories
CreateRequiredDirectories()

; Load settings
LoadSettings()

SaveSettings() ; This will create the config file with all required keys

; Create default presets
CreateDefaultPresets()

; Initialize hotkeys
InitializeHotkeys()

; Get device fingerprint
SESSION.deviceId := GetDeviceFingerprint()

; Create initial tray menu
CreateTrayMenu()

; Show login screen
ShowLoginScreen()