using System.Diagnostics;

namespace Antivirus.Core.Diagnostics;
public static class MemoryGuard
{
    private static readonly Dictionary<string, long> _lastCheck = new();

    [Conditional("DEBUG")]
    public static void Check(string location)
    {
        GC.Collect();
        GC.WaitForPendingFinalizers();

        long memory = GC.GetTotalMemory(false);
        Console.WriteLine($"[{location}] Память: {memory / 1024 / 1024} MB");

        _lastCheck[location] = memory;
    }

    [Conditional("DEBUG")]
    public static void Compare(string location, long thresholdBytes = 10 * 1024 * 1024)
    {
        if (_lastCheck.TryGetValue(location, out var previous))
        {
            long current = GC.GetTotalMemory(false);
            long diff = current - previous;

            if (diff > thresholdBytes)
            {
                Console.WriteLine($"Потенциальная утечка в {location}: +{diff / 1024 / 1024} MB");
            }
        }
    }
}

