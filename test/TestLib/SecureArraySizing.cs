// <copyright file="SecureArraySizing.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace TestLib;

using Isopoh.Cryptography.SecureArray;
using Xunit.Abstractions;

/// <summary>
/// Determines the maximum size of the secure array through binary search.
/// </summary>
public static class SecureArraySizing
{
    /// <summary>
    /// Test the buffer size <see cref="SecureArray"/> allows.
    /// </summary>
    /// <param name="output">Used to write output.</param>
    /// <returns>
    /// Result string.
    /// </returns>
    /// <remarks>
    /// <see cref="SecureArray"/> does this to some extent internally when throwing its failed exception.
    /// </remarks>
    public static (bool Passed, string Message) Test(ITestOutputHelper output)
    {
        var size = 100;
        var smallestFailedSize = int.MaxValue;
        int largestSuccessfulSize = size;
        while (true)
        {
            try
            {
                using (new SecureArray<byte>(size, SecureArray.DefaultCall))
                {
                    output.WriteLine($"SecureArray: Passed size={size}");
                    if (size + 1 >= smallestFailedSize)
                    {
                        break;
                    }

                    if (size > largestSuccessfulSize)
                    {
                        largestSuccessfulSize = size;
                    }

                    size = largestSuccessfulSize + ((smallestFailedSize - largestSuccessfulSize) / 2);
                }
            }

            // ReSharper disable once CatchAllClause
            catch (Exception e)
            {
                output.WriteLine($"SecureArray: Failed size={size}: {e.Message}");

                smallestFailedSize = size;
                long tmp = largestSuccessfulSize;
                tmp += smallestFailedSize;
                tmp /= 2;
                size = (int)tmp;

                if (smallestFailedSize <= largestSuccessfulSize)
                {
                    size = largestSuccessfulSize;
                    break;
                }
            }
        }

        return (true, $"Made a {size}-byte secure array");
    }
}
