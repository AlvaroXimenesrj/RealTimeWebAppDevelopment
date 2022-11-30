using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace ASC.Utilities
{
    public static class SessionExtensions
    {
        //public static void SetSession(this ISession session, string key, object value)
        public static void SetSession<T>(this ISession session, string key, T value)
        {
            var valor = JsonSerializer.Serialize(value);
                session.SetString(key, valor);        
            

            //session.Set(key, Encoding.ASCII.GetBytes(JsonSerializer.Serialize(value)));
        }

        public static T? Get<T>(this ISession session, string key)
        {
            byte[] value;
            if (session.TryGetValue(key, out value))
            {
                return JsonSerializer.Deserialize<T>(Encoding.ASCII.GetString(value));
            }
            else
            {
                return default(T);
            }
        }

        //public static T GetSession<T>(this ISession session, string key)
        //{
        //    byte[] value;
        //    if (session.TryGetValue(key, out value))
        //    {
        //        return JsonSerializer.Deserialize<T>(Encoding.ASCII.GetString(value));
        //    }
        //    else
        //    {
        //        return default(T);
        //    }
        //}
    }
}
