namespace Antivirus.Core.Models;
public sealed class ScanResult
{
    public required string FilePath { get; init; }
    public bool IsMalicious { get; init; }
    public string? Reason { get; init; }
}
