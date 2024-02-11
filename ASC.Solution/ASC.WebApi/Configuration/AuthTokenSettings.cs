namespace ASC.WebApi.Configuration
{
    public class AuthTokenSettings
    {
        public string Audience { get; set; }
        public string Issuer { get; set; }
        public string Secret { get; set; }
        public int ExpireHours { get; set; }
    }
}
