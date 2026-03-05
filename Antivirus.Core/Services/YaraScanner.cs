using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Antivirus.Core.Models;

namespace Antivirus.Core.Services;

public sealed class YaraScanner : IFileScanner
{
    private readonly List<MalwareRule> _rules;
    private readonly HashSet<string> _legitimateInstallers;
    //под иснталлер и правила
    public YaraScanner()
    {
        _rules = LoadRules();
        _legitimateInstallers = LoadLegitimateInstallers();
    }
    //кор правила основной чек 
    private List<MalwareRule> LoadRules()
    {
        var rules = new List<MalwareRule>();

        
        rules.Add(new MalwareRule
        {
            Name = "basic_malware_check",
            Description = "Basic malware pattern detection",
            Severity = "medium",
            Patterns = new[] { "malware", "trojan", "virus", "worm", "ransomware", "backdoor", "rootkit", "keylogger", "stealer" },
            RequiresMZ = true,
            MinMatches = 2
        });

        rules.Add(new MalwareRule
        {
            Name = "network_suspicious",
            Description = "Suspicious network activity patterns",
            Severity = "low",
            Patterns = new[] { "socket", "connect", "bind", "listen", "accept", "http://", "https://", "ftp://" },
            MinMatches = 3
        });

        rules.Add(new MalwareRule
        {
            Name = "crypto_mining",
            Description = "Cryptocurrency mining malware detection",
            Severity = "high",
            Patterns = new[] { "xmrig", "miner", "mining", "bitcoin", "ethereum", "monero", "cryptocurrency", "wallet", "pool", "miningpool" },
            MinMatches = 2
        });

        rules.Add(new MalwareRule
        {
            Name = "keylogger_patterns",
            Description = "Keylogger malware detection",
            Severity = "high",
            Patterns = new[] { "keylog", "keystroke", "keyboard", "SetWindowsHookEx", "WH_KEYBOARD", "log.txt", "keys.log", "capture", "record" },
            MinMatches = 1
        });

        rules.Add(new MalwareRule
        {
            Name = "ransomware_extensions",
            Description = "Ransomware file extension patterns",
            Severity = "critical",
            Patterns = new[] { ".encrypted", ".locked", ".crypt", ".crypted", ".aes", ".rsa", ".btc", ".ransom", "README.txt", "HOW_TO_DECRYPT.txt", "your files are encrypted" },
            MinMatches = 2
        });

        rules.Add(new MalwareRule
        {
            Name = "suspicious_executables",
            Description = "Suspicious executable patterns",
            Severity = "medium",
            Patterns = new[] { "svchost.exe", "explorer.exe", "system32", "windows\\system32", "autorun", "startup", "regedit", "registry" },
            MinMatches = 4
        });

        rules.Add(new MalwareRule
        {
            Name = "exploit_patterns",
            Description = "Common exploit patterns",
            Severity = "high",
            Patterns = new[] { "buffer overflow", "stack overflow", "inject", "dll injection", "exploit", "vulnerability" },
            MinMatches = 1
        });

        rules.Add(new MalwareRule
        {
            Name = "suspicious_powershell",
            Description = "Suspicious PowerShell usage",
            Severity = "medium",
            Patterns = new[] { "powershell", "Invoke-Expression", "IEX", "DownloadString", "WebClient", "-EncodedCommand", "-ExecutionPolicy Bypass", "base64", "-join", "[char]" },
            MinMatches = 2
        });

        rules.Add(new MalwareRule
        {
            Name = "suspicious_registry",
            Description = "Suspicious registry operations",
            Severity = "medium",
            Patterns = new[] { "HKEY_LOCAL_MACHINE", "HKEY_CURRENT_USER", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "reg add", "reg delete", "reg query" },
            MinMatches = 3
        });

        rules.Add(new MalwareRule
        {
            Name = "suspicious_dll",
            Description = "Suspicious DLL loading patterns",
            Severity = "medium",
            Patterns = new[] { "LoadLibrary", "GetProcAddress", "kernel32.dll", "user32.dll", "ntdll.dll", "VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread" },
            MinMatches = 2
        });

        rules.Add(new MalwareRule
        {
            Name = "suspicious_file_operations",
            Description = "Suspicious file system operations",
            Severity = "low",
            Patterns = new[] { "DeleteFile", "MoveFile", "CopyFile", "CreateFile", "CreateDirectory", "RemoveDirectory", "FindFirstFile", "FindNextFile" },
            MinMatches = 4
        });

        return rules;
    }

    private HashSet<string> LoadLegitimateInstallers()
    {
        return new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            // установщики
            "innosetup",
            "nsis",
            "installshield",
            "wise installer",
            "advanced installer",
            "clickteam",
            "setup factory",
            "actual installer",
            "ghost installer",

            // Системные компоненты
            "windows installer",
            "microsoft installer",
            "system center",
            "windows update",
            "microsoft update",

            // Разработческие инструменты
            "visual studio installer",
            "dotnet installer",
            "java installer",
            "python installer",
            "node.js installer",

            // Популярное ПО
            "chrome installer",
            "firefox installer",
            "vlc installer",
            "7zip installer",
            "winrar installer"
        };
    }
    //скан чекает 
    public ScanResult ScanFile(string filePath)
    {
#if DEBUG
        CheckMemory($"SCAN ДО: {Path.GetFileName(filePath)}");
#endif

        try
        {
            if (!File.Exists(filePath))
            {
                return new ScanResult
                {
                    FilePath = filePath,
                    IsMalicious = false,
                    Reason = "File not found"
                };
            }

            using var stream = File.OpenRead(filePath);
            var hash = SHA256.HashData(stream);
            var hashHex = Convert.ToHexString(hash);

            string content;
            try
            {
                content = File.ReadAllText(filePath);
            }
            catch
            {
                var bytes = File.ReadAllBytes(filePath);
                content = BitConverter.ToString(bytes.Take(256).ToArray()).Replace("-", " ");
                if (bytes.Length >= 2 && bytes[0] == 0x4D && bytes[1] == 0x5A)
                {
                    content = "MZ " + content;
                }
            }

            var matchedRules = new List<string>();
            var fileInfo = new FileInfo(filePath);

            bool isPotentialInstaller = IsPotentialInstaller(filePath, content, fileInfo.Length);

            foreach (var rule in _rules)
            {
                if (MatchesRule(content, rule))
                {
                    matchedRules.Add(rule.Name);
                }
            }

            if (matchedRules.Count > 0)
            {
                if (isPotentialInstaller && IsLikelyLegitimateInstaller(content, matchedRules))
                {
                    return new ScanResult
                    {
                        FilePath = filePath,
                        IsMalicious = false,
                        Reason = $"Legitimate installer detected (contains: {string.Join(", ", matchedRules)}). SHA256={hashHex}"
                    };
                }

                string threatLevel = DetermineThreatLevel(matchedRules, fileInfo.Length, content.Length);

                return new ScanResult
                {
                    FilePath = filePath,
                    IsMalicious = true,
                    Reason = $"[{threatLevel}] Detected malware patterns: {string.Join(", ", matchedRules)}. SHA256={hashHex}"
                };
            }
            else
            {
                return new ScanResult
                {
                    FilePath = filePath,
                    IsMalicious = false,
                    Reason = $"No threats detected. SHA256={hashHex}"
                };
            }
        }
        catch (Exception ex)
        {
            return new ScanResult
            {
                FilePath = filePath,
                IsMalicious = false,
                Reason = $"Scan error: {ex.Message}"
            };
        }
        finally
        {
#if DEBUG
            CheckMemory($"SCAN ПОСЛЕ: {Path.GetFileName(filePath)}");
#endif
        }
    }
    //проверка правил
    private bool MatchesRule(string content, MalwareRule rule)
    {
        if (rule.RequiresMZ && !content.StartsWith("MZ"))
        {
            return false;
        }

        int matchCount = 0;
        foreach (var pattern in rule.Patterns)
        {
            if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
            {
                matchCount++;
                if (rule.MinMatches == 1) 
                {
                    return true;
                }
            }
        }

        return matchCount >= rule.MinMatches;
    }

    private bool IsPotentialInstaller(string filePath, string content, long fileSize)
    {
        var fileName = Path.GetFileName(filePath).ToLower();

        //имя файла, явные признаки установщика короче по имени смотрю (честно спорно но работает мне понравилось вот и сделал)
        if (fileName.Contains("setup") || fileName.Contains("install") || fileName.Contains("installer"))
        {
            return true;
        }

        
        bool hasInstallerStrings = false;
        foreach (var installer in _legitimateInstallers)
        {
            if (content.Contains(installer, StringComparison.OrdinalIgnoreCase))
            {
                hasInstallerStrings = true;
                break;
            }
        }

        
        if (hasInstallerStrings)
        {
            return true;
        }

        
        if (fileSize > 10 * 1024 * 1024) // 10MB
        {
            
            string[] archiveMarkers = { "zip", "cab", "rar", "7z", "nsis", "inno", "wise" };
            foreach (var marker in archiveMarkers)
            {
                if (content.Contains(marker, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
        }

        return false;
    }

    private bool IsLikelyLegitimateInstaller(string content, List<string> matchedRules)
    {
        
        bool hasStrongLegitimacyIndicators = false;
        string[] legitimacyMarkers = {
            "inno setup", "nsis", "microsoft corporation", "windows installer",
            "installshield", "wise installer", "advanced installer"
        };

        foreach (var marker in legitimacyMarkers)
        {
            if (content.Contains(marker, StringComparison.OrdinalIgnoreCase))
            {
                hasStrongLegitimacyIndicators = true;
                break;
            }
        }

        // считаем установщиком
        if (hasStrongLegitimacyIndicators)
        {
            return true;
        }

        
        var hardRules = new[] { "crypto_mining", "keylogger_patterns", "exploit_patterns", "ransomware_extensions" };
        var mediumRules = new[] { "suspicious_dll", "suspicious_powershell" };
        var softRules = new[] { "network_suspicious", "suspicious_file_operations", "suspicious_registry", "suspicious_executables" };

        int hardMatches = matchedRules.Count(rule => hardRules.Contains(rule));
        int mediumMatches = matchedRules.Count(rule => mediumRules.Contains(rule));
        int softMatches = matchedRules.Count(rule => softRules.Contains(rule));

        // Если есть совпадения с критическими вирусами, то точно не легитимный установщик
        if (hardMatches > 0)
        {
            return false;
        }

        // Если только мягкие вирусы и не больше 3 совпадений то может быть легитимным
        if (mediumMatches == 0 && softMatches > 0 && matchedRules.Count <= 3)
        {
            return true;
        }

        // По умолчанию не считаем легитимным установщиком
        return false;
    }

    private string DetermineThreatLevel(List<string> matchedRules, long fileSize, int contentLength)
    {
        int riskScore = 0;

        // Оценка по правилам
        foreach (var rule in matchedRules)
        {
            switch (rule)
            {
                case "ransomware_extensions":
                case "exploit_patterns":
                case "crypto_mining":
                    riskScore += 3;
                    break;
                case "keylogger_patterns":
                case "suspicious_dll":
                    riskScore += 2;
                    break;
                default:
                    riskScore += 1;
                    break;
            }
        }

        // чек размера
        if (fileSize < 1024) // < 1KB
            riskScore += 2;
        else if (fileSize > 100 * 1024 * 1024) // > 100MB
            riskScore += 1;

        // уровень угрозы
        if (riskScore >= 5)
            return "CRITICAL";
        else if (riskScore >= 3)
            return "HIGH";
        else if (riskScore >= 2)
            return "MEDIUM";
        else
            return "LOW";
    }

#if DEBUG
    public static void CheckMemory(string place)
    {
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        long memory = GC.GetTotalMemory(false);
        Console.WriteLine($"[{place}] {memory / 1024 / 1024} MB");
    }
#endif

    public IEnumerable<ScanResult> ScanDirectory(string directoryPath, string? pattern = null, bool recursive = true)
    {
        var results = new List<ScanResult>();

        if (!Directory.Exists(directoryPath))
        {
            results.Add(new ScanResult
            {
                FilePath = directoryPath,
                IsMalicious = false,
                Reason = "Directory not found"
            });
        }
        else
        {
            var searchPattern = pattern ?? "*.*";
            var searchOption = recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(directoryPath, searchPattern, searchOption);
            }
            catch (Exception ex)
            {
                results.Add(new ScanResult
                {
                    FilePath = directoryPath,
                    IsMalicious = false,
                    Reason = $"Directory scan error: {ex.Message}"
                });
                files = Array.Empty<string>();
            }

            foreach (var file in files)
            {
                try
                {
                    results.Add(ScanFile(file));
                }
                catch (Exception ex)
                {
                    results.Add(new ScanResult
                    {
                        FilePath = file,
                        IsMalicious = false,
                        Reason = $"Scan error: {ex.Message}"
                    });
                }
            }
        }

        foreach (var result in results)
        {
            yield return result;
        }
    }
}

public class MalwareRule
{
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty;
    public string[] Patterns { get; set; } = Array.Empty<string>();
    public bool RequiresMZ { get; set; } = false;
    public int MinMatches { get; set; } = 1;
}
