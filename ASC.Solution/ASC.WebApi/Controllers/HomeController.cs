using ASC.WebApi.Configuration;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace ASC.WebApi.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class HomeController : ControllerBase
    {
        private IOptions<ApplicationSettings> _settings;  
        private readonly ILogger<HomeController> _logger;

        public HomeController(
            ILogger<HomeController> logger,
            IOptions<ApplicationSettings> settings)
        {
            _logger = logger;
            _settings = settings;
        }

        [HttpGet]
        public async Task<IActionResult> Get()
        {
            return Ok(_settings.Value.ApplicationTitle);
        }
    }
}