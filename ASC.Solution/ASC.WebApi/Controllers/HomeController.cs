using ASC.Utilities;
using ASC.WebApi.Configuration;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace ASC.WebApi.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class HomeController : ControllerBase
    {
        private IOptions<ApplicationSettings> _settings;  
       // private readonly ILogger<HomeController> _logger;

        public HomeController(
           // ILogger<HomeController> logger,
            IOptions<ApplicationSettings> settings)
        {
           // _logger = logger;
            _settings = settings;
        }

        [HttpGet]
        public async Task<IActionResult> Get()
        {
            // TEST SESSION
            // Set Session
            HttpContext.Session.SetSession("Teste", _settings.Value);
            // Get Session
            var settings = HttpContext.Session.Get<ApplicationSettings>("Teste");
          //  HttpContext.Session.Set<DateTime>(SessionKeyTime, currentTime)
            // Usage of IOptions
            //ViewBag.Title = _settings.Value.ApplicationTitle;
            return Ok(settings.ApplicationTitle);
        }
    }
}