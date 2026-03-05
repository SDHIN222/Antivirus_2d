using Antivirus.Core.Models;

namespace Antivirus.Core.Services;

public interface IFileScanner
{
    ScanResult ScanFile(string filePath);
    IEnumerable<ScanResult> ScanDirectory(string directoryPath, string? pattern = null, bool recursive = true);
}
