// <copyright file="Program.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace DumpTimings
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;

    using Isopoh.Cryptography.Argon2;

    /// <summary>
    /// The program that dumps timings
    /// </summary>
    public class Program
    {
        private static readonly List<ParallelismScheme> ParallelSchemes
            = Enum.GetValues(typeof(ParallelismScheme)).Cast<ParallelismScheme>().ToList();

        private static readonly List<UnrollScheme> UnrollSchemes =
            Enum.GetValues(typeof(UnrollScheme)).Cast<UnrollScheme>().ToList();

        /// <summary>
        /// The program entry point
        /// </summary>
        /// <param name="args">
        /// Command line arguments (unused).
        /// </param>
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
            var results = new Table();
            long doneTicks = testMinTime.Ticks * ParallelSchemes.Count * UnrollSchemes.Count;
            for (int memoryCost = 16 * 4 * 4 * 4 * 4 * 4 * 4; memoryCost <= 16 * 4 * 4 * 4 * 4 * 4 * 4 * 4 * 4; memoryCost *= 4)
            {
                int memoryBlockCount = 0;
                int laneLength = 0;
                int segmentLength = 0;
                bool done = false;
                for (int c = 0; c < maxCount || !done; ++c)
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
                                                 MemoryCost = memoryCost,
                                                 Lanes = 4,
                                                 Threads = 4,
                                                 ParallelismScheme = ps,
                                                 UnrollScheme = us
                                             };
                            try
                            {
                                using (var argon2 = new Argon2(config))
                                {
                                    var ts = DateTime.UtcNow.Ticks;
                                    using (argon2.Hash())
                                    {
                                        var d = DateTime.UtcNow.Ticks - ts;
                                        done |= results.Add($"{ps} {us}", memoryCost, d) > doneTicks;
                                    }

                                    memoryBlockCount = argon2.MemoryBlockCount;
                                    laneLength = argon2.LaneLength;
                                    segmentLength = argon2.SegmentLength;
                                }
                            }
                            catch (OutOfMemoryException)
                            {
                                Console.WriteLine(
                                    $"Out of memory for memory cost {memoryCost} even with Garbage Collection ({GC.GetTotalMemory(true)} bytes currently allocated)");
                            }
                        }
                    }
                }

                Console.WriteLine($"  MemoryBlockCount: {memoryBlockCount}, LaneLength: {laneLength}, SegmentLength: {segmentLength}");
            }

            Console.WriteLine("Lanes=4 Threads=4");
            results.DumpCsv("Memory Cost");
        }

        private static void VaryLanes(byte[] passwordBytes, TimeSpan testMinTime, int maxCount)
        {
            Console.WriteLine("Seconds per Lane (Memory Cost=16536, Threads=4)");
            var results = new Table();
            long doneTicks = testMinTime.Ticks * ParallelSchemes.Count * UnrollSchemes.Count;
            for (int lanes = 1; lanes <= 512; lanes *= 2)
            {
                int memoryBlockCount = 0;
                int laneLength = 0;
                int segmentLength = 0;
                bool done = false;
                for (int c = 0; c < maxCount || !done; ++c)
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
                                                 MemoryCost = 16536,
                                                 Lanes = lanes,
                                                 Threads = 4
                                             };
                            using (var argon2 = new Argon2(config))
                            {
                                var ts = DateTime.UtcNow.Ticks;
                                using (argon2.Hash())
                                {
                                    var d = DateTime.UtcNow.Ticks - ts;
                                    done |= results.Add($"{ps} {us}", lanes, d) > doneTicks;
                                }

                                memoryBlockCount = argon2.MemoryBlockCount;
                                laneLength = argon2.LaneLength;
                                segmentLength = argon2.SegmentLength;
                            }
                        }
                    }
                }

                Console.WriteLine($"  MemoryBlockCount: {memoryBlockCount}, LaneLength: {laneLength}, SegmentLength: {segmentLength}");
            }

            Console.WriteLine("Memory Cost=16536 Threads=4");
            results.DumpCsv("Lanes");
        }

        private static void VaryThreads(byte[] passwordBytes, TimeSpan testMinTime, int maxCount)
        {
            var results = new Table();
            long doneTicks = testMinTime.Ticks * ParallelSchemes.Count * UnrollSchemes.Count;
            int max = Environment.ProcessorCount * 2;
            foreach (var memoryCost in new List<int> { 8192, 8192 * 4, 8192 * 4 * 4 })
            {
                Console.WriteLine($"Seconds per Thread (Memory Cost={memoryCost} Lanes={max})");
                for (int threads = 1; threads <= max; threads += threads < Environment.ProcessorCount ? 1 : 2)
                {
                    int memoryBlockCount = 0;
                    int laneLength = 0;
                    int segmentLength = 0;
                    bool done = false;
                    for (int c = 0; c < maxCount || !done; ++c)
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
                                                     MemoryCost = memoryCost,
                                                     Lanes = max,
                                                     Threads = threads
                                                 };
                                using (var argon2 = new Argon2(config))
                                {
                                    var ts = DateTime.UtcNow.Ticks;
                                    using (argon2.Hash())
                                    {
                                        var d = DateTime.UtcNow.Ticks - ts;
                                        done |= results.Add($"{ps} {us}", threads, d) > doneTicks;
                                    }

                                    memoryBlockCount = argon2.MemoryBlockCount;
                                    laneLength = argon2.LaneLength;
                                    segmentLength = argon2.SegmentLength;
                                }
                            }
                        }
                    }

                    Console.WriteLine($"  MemoryBlockCount: {memoryBlockCount}, LaneLength: {laneLength}, SegmentLength: {segmentLength}");
                }

                Console.WriteLine($"Memory Cost={memoryCost}, Lanes={max}");
                results.DumpCsv("Threads");
            }
        }

        /// <summary>
        /// The results table
        /// </summary>
        public class Table
        {
            /// <summary>
            /// Gets the columns
            /// </summary>
            public Dictionary<int, Column> Columns { get; } = new Dictionary<int, Column>();

            /// <summary>
            /// Add ticks to a cell.
            /// </summary>
            /// <param name="row">
            /// The row of the cell
            /// </param>
            /// <param name="column">
            /// The column of the cell.
            /// </param>
            /// <param name="ticks">
            /// The ticks to add to the cell.
            /// </param>
            /// <returns>
            /// The total number of ticks added to the cell.
            /// </returns>
            public long Add(string row, int column, long ticks)
            {
                Column c;
                if (!this.Columns.TryGetValue(column, out c))
                {
                    c = new Column();
                    this.Columns.Add(column, c);
                }

                return c.Add(row, ticks);
            }

            /// <summary>
            /// Write out the CSV table.
            /// </summary>
            /// <param name="xAxisTitle">
            /// The X-axis title.
            /// </param>
            public void DumpCsv(string xAxisTitle)
            {
                var tmpRows = new HashSet<string>();
                foreach (var column in this.Columns.Values)
                {
                    foreach (var row in column.Cells.Keys)
                    {
                        tmpRows.Add(row);
                    }
                }

                var rows = tmpRows.ToList();
                rows.Sort();
                var columns = this.Columns.Keys.ToList();
                columns.Sort();

                Console.WriteLine($"{xAxisTitle},{string.Join(",", columns)}");
                foreach (var row in rows)
                {
                    Console.WriteLine(
                        $"{row},{string.Join(",", this.Columns.Values.Select(c => c.Milliseconds(row)))}");
                }
            }
        }

        /// <summary>
        /// The results column
        /// </summary>
        public class Column
        {
            /// <summary>
            /// Gets the cells in the column
            /// </summary>
            public Dictionary<string, Cell> Cells { get; } = new Dictionary<string, Cell>();

            /// <summary>
            /// Add a value to the column
            /// </summary>
            /// <param name="row">
            /// The row to add the value to.
            /// </param>
            /// <param name="ticks">
            /// The value.
            /// </param>
            /// <returns>
            /// The total ticks added to the cell.
            /// </returns>
            public long Add(string row, long ticks)
            {
                Cell cell;
                if (!this.Cells.TryGetValue(row, out cell))
                {
                    cell = new Cell();
                    this.Cells.Add(row, cell);
                }

                return cell.Add(ticks);
            }

            /// <summary>
            /// Return the milliseconds for a given row.
            /// </summary>
            /// <param name="row">
            /// The row to return the value for.
            /// </param>
            /// <returns>
            /// The number of milleseconds in the given row.
            /// </returns>
            public double Milliseconds(string row)
            {
                Cell cell;
                return this.Cells.TryGetValue(row, out cell) ? cell.Milliseconds : 0;
            }
        }

        /// <summary>
        /// The result cell.
        /// </summary>
        public class Cell
        {
            /// <summary>
            /// Gets the total number of ticks added
            /// </summary>
            public long Ticks { get; private set; }

            /// <summary>
            /// Gets the number of times ticks were added.
            /// </summary>
            public long Count { get; private set; }

            /// <summary>
            /// Gets the average milliseconds per add.
            /// </summary>
            public double Milliseconds => this.Count == 0 ? 0 : (double)this.Ticks / this.Count / TimeSpan.TicksPerMillisecond;

            /// <summary>
            /// Add ticks to the cell.
            /// </summary>
            /// <param name="ticks">
            /// The number of ticks to add
            /// </param>
            /// <returns>
            /// The total ticks added.
            /// </returns>
            public long Add(long ticks)
            {
                this.Ticks += ticks;
                ++this.Count;
                return this.Ticks;
            }
        }
    }
}
