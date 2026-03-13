package com.paramhunter;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public class WordlistManager {

    private final List<String> defaultWordlist;
    private List<String> activeWordlist;

    public WordlistManager() {
        defaultWordlist = loadDefaultWordlist();
        activeWordlist = new ArrayList<>(defaultWordlist);
    }

    private List<String> loadDefaultWordlist() {
        List<String> words = new ArrayList<>();
        try (InputStream is = getClass().getClassLoader().getResourceAsStream("default_wordlist.txt")) {
            if (is != null) {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        String trimmed = line.trim();
                        if (!trimmed.isEmpty() && !trimmed.startsWith("#")) {
                            words.add(trimmed);
                        }
                    }
                }
            }
        } catch (IOException e) {
            // Fall through to hardcoded fallback
        }

        if (words.isEmpty()) {
            words = getHardcodedWordlist();
        }
        return words;
    }

    public void loadCustomWordlist(Path filePath) throws IOException {
        Set<String> merged = new LinkedHashSet<>(defaultWordlist);
        List<String> lines = Files.readAllLines(filePath, StandardCharsets.UTF_8);
        for (String line : lines) {
            String trimmed = line.trim();
            if (!trimmed.isEmpty() && !trimmed.startsWith("#")) {
                merged.add(trimmed);
            }
        }
        activeWordlist = new ArrayList<>(merged);
    }

    public void resetToDefault() {
        activeWordlist = new ArrayList<>(defaultWordlist);
    }

    public List<String> getActiveWordlist() {
        return activeWordlist;
    }

    public int getWordlistSize() {
        return activeWordlist.size();
    }

    /**
     * Returns wordlist minus already-known parameter names.
     */
    public List<String> getFilteredWordlist(Set<String> knownParams) {
        List<String> filtered = new ArrayList<>();
        for (String param : activeWordlist) {
            if (!knownParams.contains(param.toLowerCase())) {
                filtered.add(param);
            }
        }
        return filtered;
    }

    private List<String> getHardcodedWordlist() {
        List<String> w = new ArrayList<>();
        String[] params = {
            "id", "user", "username", "name", "email", "password", "pass", "passwd",
            "token", "auth", "key", "api_key", "apikey", "api-key", "access_token",
            "secret", "secret_key", "client_id", "client_secret", "session",
            "sessionid", "session_id", "csrf", "csrf_token", "nonce",
            "debug", "test", "testing", "admin", "administrator", "root",
            "callback", "redirect", "redirect_uri", "redirect_url", "return",
            "returnUrl", "return_url", "returnTo", "return_to", "next", "url",
            "forward", "dest", "destination", "redir", "out", "view", "dir",
            "show", "display", "page", "p", "pg", "offset", "limit", "count",
            "size", "num", "number", "start", "end", "from", "to",
            "format", "output", "type", "content", "content_type", "accept",
            "ref", "reference", "referer", "source", "src", "origin",
            "action", "act", "cmd", "command", "exec", "execute", "run",
            "do", "func", "function", "method", "mode", "module",
            "step", "state", "status", "code", "error", "msg", "message",
            "text", "comment", "body", "data", "payload", "input",
            "query", "q", "search", "keyword", "keywords", "term", "terms",
            "filter", "sort", "order", "orderby", "order_by", "sortby", "sort_by",
            "asc", "desc", "direction", "group", "groupby", "group_by",
            "field", "fields", "column", "columns", "select", "include",
            "exclude", "expand", "embed", "with", "join", "relation",
            "file", "filename", "filepath", "path", "folder", "upload",
            "download", "attachment", "image", "img", "photo", "pic",
            "avatar", "icon", "logo", "banner", "cover", "thumbnail",
            "width", "height", "w", "h", "x", "y", "lat", "lng",
            "latitude", "longitude", "location", "address", "city",
            "region", "country", "zip", "zipcode", "postal", "phone",
            "mobile", "tel", "fax", "firstname", "lastname", "first_name",
            "last_name", "full_name", "fullname", "nick", "nickname",
            "title", "subject", "description", "desc", "summary", "bio",
            "about", "info", "details", "note", "notes", "label",
            "tag", "tags", "category", "categories", "cat", "class",
            "role", "roles", "permission", "permissions", "scope", "scopes",
            "grant", "grant_type", "response_type", "access", "level",
            "priority", "weight", "rank", "rating", "score", "points",
            "price", "cost", "amount", "total", "subtotal", "tax",
            "discount", "coupon", "promo", "promotion", "voucher",
            "currency", "lang", "language", "locale", "timezone", "tz",
            "date", "time", "datetime", "timestamp", "year", "month",
            "day", "hour", "minute", "second", "duration", "interval",
            "created", "created_at", "updated", "updated_at", "modified",
            "deleted", "deleted_at", "expires", "expiry", "expire",
            "ttl", "max_age", "cache", "no_cache", "refresh",
            "version", "v", "ver", "rev", "revision", "build",
            "release", "branch", "tag", "commit", "hash", "checksum",
            "signature", "sign", "verify", "validate", "confirm",
            "approve", "reject", "cancel", "close", "open", "lock",
            "unlock", "enable", "disable", "active", "inactive",
            "visible", "hidden", "public", "private", "internal",
            "external", "local", "remote", "global", "default",
            "custom", "config", "configuration", "setting", "settings",
            "option", "options", "preference", "preferences", "param",
            "params", "parameter", "parameters", "arg", "args",
            "argument", "arguments", "attr", "attribute", "attributes",
            "prop", "property", "properties", "meta", "metadata",
            "header", "headers", "cookie", "cookies", "agent",
            "user_agent", "ip", "host", "hostname", "domain",
            "subdomain", "port", "protocol", "scheme", "ssl", "tls",
            "https", "http", "ftp", "smtp", "imap", "pop",
            "proxy", "gateway", "router", "server", "client",
            "app", "application", "service", "api", "endpoint",
            "route", "resource", "object", "entity", "model",
            "table", "collection", "database", "db", "schema",
            "namespace", "prefix", "suffix", "index", "idx",
            "primary", "secondary", "alternate", "backup", "fallback",
            "timeout", "retry", "retries", "max_retries", "delay",
            "wait", "sleep", "interval", "poll", "frequency",
            "batch", "bulk", "chunk", "block", "segment",
            "part", "piece", "fragment", "section", "sector",
            "verbose", "quiet", "silent", "log", "logging",
            "trace", "track", "audit", "monitor", "watch",
            "alert", "notify", "notification", "event", "trigger",
            "hook", "webhook", "listener", "handler", "processor",
            "worker", "job", "task", "queue", "pipeline",
            "channel", "topic", "exchange", "binding", "routing",
            "pattern", "regex", "match", "replace", "transform",
            "convert", "encode", "decode", "encrypt", "decrypt",
            "compress", "decompress", "serialize", "deserialize", "parse",
            "render", "template", "layout", "theme", "skin",
            "color", "colour", "background", "foreground", "border",
            "margin", "padding", "spacing", "gap", "align",
            "valign", "halign", "top", "bottom", "left", "right",
            "center", "middle", "float", "position", "absolute",
            "relative", "fixed", "sticky", "static", "dynamic",
            "async", "sync", "parallel", "sequential", "concurrent",
            "thread", "process", "pid", "uid", "gid",
            "owner", "creator", "author", "editor", "reviewer",
            "assignee", "member", "subscriber", "follower", "friend",
            "contact", "account", "profile", "dashboard", "home",
            "index", "main", "root", "base", "parent",
            "child", "children", "sibling", "ancestor", "descendant",
            "depth", "level", "tier", "layer", "stage",
            "phase", "round", "iteration", "cycle", "loop",
            "range", "min", "max", "minimum", "maximum",
            "lower", "upper", "bound", "threshold", "cap",
            "quota", "rate", "speed", "bandwidth", "throughput",
            "capacity", "load", "usage", "utilization", "consumption",
            "available", "remaining", "balance", "credit", "debit",
            "invoice", "receipt", "order", "cart", "basket",
            "item", "product", "sku", "upc", "ean",
            "isbn", "brand", "manufacturer", "vendor", "supplier",
            "merchant", "store", "shop", "market", "marketplace",
            "stock", "inventory", "quantity", "qty", "unit",
            "measure", "metric", "dimension", "length", "area",
            "volume", "mass", "weight_unit", "format_type", "encoding",
            "charset", "utf8", "ascii", "base64", "hex",
            "json", "xml", "html", "csv", "yaml",
            "plain", "raw", "binary", "stream", "buffer",
            "wsdl", "soap", "rest", "graphql", "grpc",
            "oauth", "jwt", "bearer", "basic", "digest",
            "saml", "sso", "mfa", "otp", "totp",
            "pin", "captcha", "recaptcha", "challenge", "answer",
            "question", "security_question", "recovery", "reset",
            "forgot", "change", "update", "edit", "modify",
            "patch", "put", "post", "get", "delete",
            "create", "read", "list", "fetch", "retrieve",
            "send", "receive", "push", "pull", "sync_action",
            "import", "export", "backup_action", "restore", "migrate",
            "upgrade", "downgrade", "install", "uninstall", "setup",
            "init", "initialize", "bootstrap", "seed", "populate"
        };
        for (String p : params) {
            w.add(p);
        }
        return w;
    }
}
