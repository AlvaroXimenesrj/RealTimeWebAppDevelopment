using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace ASC.Utilities
{
    public static class ObjectExtension
    {
        public static T CopyObject<T>(this object objSource)
        {
            var serialized = JsonSerializer.Serialize(objSource);
            return JsonSerializer.Deserialize<T>(serialized)!;
        }
    }
}
