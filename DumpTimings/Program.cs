namespace DumpTimings
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;

    using Isopoh.Cryptography.Argon2;

    public class Program
    {
        private static readonly List<ParallelismScheme> ParallelSchemes
            = Enum.GetValues(typeof(ParallelismScheme)).Cast<ParallelismScheme>().ToList();

        private static readonly List<UnrollScheme> UnrollSchemes =
            Enum.GetValues(typeof(UnrollScheme)).Cast<UnrollScheme>().ToList();


        public static void Main(string[] args)
        {
            var password = "password";
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            var testMinimumTime = TimeSpan.FromMinutes(3);
            const int MaxCount = 200;
            WarmUp(passwordBytes);
            VaryMemoryCost(passwordBytes, testMinimumTime, MaxCount);
            VaryLanes(passwordBytes, testMinimumTime, MaxCount);
            VaryThreads(passwordBytes, testMinimumTime, MaxCount);
        }

        private static void WarmUp(byte[] passwordBytes)
        {
            Console.WriteLine("Warm-up: calling Argon2.Hash a bunch of ways to get code paths executed");
            for (int threads = 1; threads < 3; ++threads)
            {
                foreach (var ps in ParallelSchemes)
                {
                    foreach (var us in UnrollSchemes)
                    {
                        GC.Collect();
                        GC.WaitForPendingFinalizers();
                        var config = new Argon2Config
                        {
                            Password = passwordBytes,
                            MemoryCost = 1024,
                            Lanes = 4,
                            Threads = threads,
                            ParallelismScheme = ps,
                            UnrollScheme = us
                        };
                        using (var argon2 = new Argon2(config))
                        {
                            using (argon2.Hash())
                            {
                            }
                        }
                    }
                }
            }
        }

        private static void VaryMemoryCost(byte[] passwordBytes, TimeSpan testMinTime, int maxCount)
        {
            Console.WriteLine("Seconds per Memory Cost (Lanes=4 Threads=4)");
            var results =
                ParallelSchemes.SelectMany(
                    ps => UnrollSchemes.Select(us => new { ParallelScheme = ps, UnrollScheme = us }))
                    .ToDictionary(
                        x => $"{x.ParallelScheme} {x.UnrollScheme}",
                        x => new List<double>());
            var xAxisValues = new List<int>();
            for (int i = 16; i <= 16 * 4 * 4 * 4 * 4 * 4 * 4 * 4 * 4; i *= 4)
            {
                xAxisValues.Add(i);
                int memoryBlockCount = 0;
                int laneLength = 0;
                int segmentLength = 0;
                foreach (var ps in ParallelSchemes)
                {
                    foreach (var us in UnrollSchemes)
                    {
                        GC.Collect();
                        GC.WaitForPendingFinalizers();
                        var config = new Argon2Config
                        {
                            Password = passwordBytes,
                            MemoryCost = i,
                            Lanes = 4,
                            Threads = 4,
                            ParallelismScheme = ps,
                            UnrollScheme = us
                        };
                        int count = 0;
                        var start = DateTimeOffset.Now;
                        var tick = start + testMinTime;
                        using (var argon2 = new Argon2(config))
                        {
                            while (DateTimeOffset.Now < tick && count < maxCount)
                            {
                                using (argon2.Hash())
                                {
                                    ++count;
                                }
                            }

                            var end = DateTimeOffset.Now;
                            var timePerRun = TimeSpan.FromTicks((end - start).Ticks / count);
                            results[$"{ps} {us}"].Add(timePerRun.TotalSeconds);
                            Console.WriteLine(
                                $"{ps} {us} MemoryCost {i}: {timePerRun.TotalMilliseconds:F1} milleseconds average over {count} runs");
                            memoryBlockCount = argon2.MemoryBlockCount;
                            laneLength = argon2.LaneLength;
                            segmentLength = argon2.SegmentLength;
                        }
                    }
                }

                Console.WriteLine($"  MemoryBlockCount: {memoryBlockCount}, LaneLength: {laneLength}, SegmentLength: {segmentLength}");
            }

            Console.WriteLine("Lanes=4 Threads=4");
            DumpResultsCsv("Memory Cost", xAxisValues, results);
        }

        private static void VaryLanes(byte[] passwordBytes, TimeSpan testMinTime, int maxCount)
        {
            Console.WriteLine("Seconds per Lane (Memory Cost=16536, Threads=4)");
            var results =
                ParallelSchemes.SelectMany(
                    ps => UnrollSchemes.Select(us => new { ParallelScheme = ps, UnrollScheme = us }))
                    .ToDictionary(
                        x => $"{x.ParallelScheme} {x.UnrollScheme}",
                        x => new List<double>());
            var xAxisValues = new List<int>();
            for (int i = 1; i <= 512; i *= 2)
            {
                int memoryBlockCount = 0;
                int laneLength = 0;
                int segmentLength = 0;
                xAxisValues.Add(i);
                foreach (var ps in ParallelSchemes)
                {
                    foreach (var us in UnrollSchemes)
                    {
                        GC.Collect();
                        GC.WaitForPendingFinalizers();
                        var config = new Argon2Config
                        {
                            Password = passwordBytes,
                            MemoryCost = 16536,
                            Lanes = i,
                            Threads = 4
                        };
                        using (var argon2 = new Argon2(config))
                        {
                            int count = 0;
                            var start = DateTimeOffset.Now;
                            var tick = start + testMinTime;
                            while (DateTimeOffset.Now < tick && count < maxCount)
                            {
                                using (argon2.Hash())
                                {
                                    ++count;
                                }
                            }

                            var end = DateTimeOffset.Now;
                            var timePerRun = TimeSpan.FromTicks((end - start).Ticks / count);
                            results[$"{ps} {us}"].Add(timePerRun.TotalSeconds);
                            Console.WriteLine(
                                $"{ps} {us} lanes {i}: {timePerRun.TotalMilliseconds:F1} milleseconds average over {count} runs");
                            memoryBlockCount = argon2.MemoryBlockCount;
                            laneLength = argon2.LaneLength;
                            segmentLength = argon2.SegmentLength;
                        }
                    }
                }

                Console.WriteLine($"  MemoryBlockCount: {memoryBlockCount}, LaneLength: {laneLength}, SegmentLength: {segmentLength}");
            }

            Console.WriteLine("Memory Cost=16536 Threads=4");
            DumpResultsCsv("Lanes", xAxisValues, results);
        }

        private static void VaryThreads(byte[] passwordBytes, TimeSpan testMinTime, int maxCount)
        {
            var results =
                ParallelSchemes.SelectMany(
                    ps => UnrollSchemes.Select(us => new { ParallelScheme = ps, UnrollScheme = us }))
                    .ToDictionary(
                        x => $"{x.ParallelScheme} {x.UnrollScheme}",
                        x => new List<double>());
            int max = Environment.ProcessorCount * 2;
            foreach (var memoryCost in new List<int> { 8192, 8192 * 4, 8192 * 4 * 4 })
            {
                Console.WriteLine($"Seconds per Thread (Memory Cost={memoryCost} Lanes={max})");
                var xAxisValues = new List<int>();
                for (int i = 1; i <= max; i += i < Environment.ProcessorCount ? 1 : 2)
                {
                    int memoryBlockCount = 0;
                    int laneLength = 0;
                    int segmentLength = 0;
                    xAxisValues.Add(i);
                    foreach (var ps in ParallelSchemes)
                    {
                        foreach (var us in UnrollSchemes)
                        {
                            GC.Collect();
                            GC.WaitForPendingFinalizers();
                            var config = new Argon2Config
                            {
                                Password = passwordBytes,
                                MemoryCost = memoryCost,
                                Lanes = max,
                                Threads = i
                            };
                            using (var argon2 = new Argon2(config))
                            {
                                int count = 0;
                                var start = DateTimeOffset.Now;
                                var tick = start + testMinTime;
                                while (DateTimeOffset.Now < tick && count < maxCount)
                                {
                                    using (argon2.Hash())
                                    {
                                        ++count;
                                    }
                                }

                                var end = DateTimeOffset.Now;
                                var timePerRun = TimeSpan.FromTicks((end - start).Ticks / count);
                                results[$"{ps} {us}"].Add(timePerRun.TotalSeconds);
                                Console.WriteLine(
                                    $"{ps} {us} Threads {i}: {timePerRun.TotalMilliseconds:F1} milleseconds average over {count} runs");
                                memoryBlockCount = argon2.MemoryBlockCount;
                                laneLength = argon2.LaneLength;
                                segmentLength = argon2.SegmentLength;
                            }
                        }
                    }

                    Console.WriteLine($"  MemoryBlockCount: {memoryBlockCount}, LaneLength: {laneLength}, SegmentLength: {segmentLength}");
                }

                Console.WriteLine($"Memory Cost={memoryCost}, Lanes={max}");
                DumpResultsCsv("Threads", xAxisValues, results);
            }
        }

        private static void DumpResultsCsv(string xAxisTitle, List<int> xAxisValues, Dictionary<string, List<double>> results)
        {
            Console.WriteLine($"{xAxisTitle},{string.Join(",", results.Keys)}");
            for (int row = 0; row < xAxisValues.Count; ++row)
            {
                var valueRow = row;
                var values = results.Values.Select(v => v[valueRow]);
                Console.WriteLine($"{xAxisValues[row]},{string.Join(",", values)}");
            }
        }
    }
}
