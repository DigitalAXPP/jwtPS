using System.Collections;
using System.Collections.Generic;
using System.Linq;

namespace jwtPS.Extension
{
    public static class Extensions
    {
        public static Dictionary<K, V> ToDictionary<K, V>(this Hashtable Table)
        {
            return Table

                .Cast<DictionaryEntry>()
                .ToDictionary(kvp => (K)kvp.Key, kvp => (V)kvp.Value);
        }
    }
}
