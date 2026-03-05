using System.Security.Cryptography;
using System.Text;
using Antivirus.Core.Models;
//старый варик
namespace Antivirus.Core.Services;

public sealed class SimpleFileScanner : IFileScanner
{
    public ScanResult ScanFile(string filePath)
    {

        using var stream = File.OpenRead(filePath);
        var hash = SHA256.HashData(stream);
        var hashHex = Convert.ToHexString(hash);
        return new ScanResult
        {
            FilePath = filePath,
            IsMalicious = false,
            Reason = $"SHA256={hashHex}"
        };
    }

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
