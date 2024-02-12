using ASC.WebApi.Configuration;
using ASC.WebApi.Identity;
using ASC.WebApi.Models;
using ASC.WebApi.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi.Models;
using System.Text;

namespace ASC.WebApi
{
    public class Startup
    {
        public IConfiguration Configuration { get; }
        public Startup(IHostEnvironment hostEnvironment)
        {
            #region appSettings
            var builder = new ConfigurationBuilder()
                .SetBasePath(hostEnvironment.ContentRootPath)
                .AddJsonFile("appsettings.json", true, true)
                .AddJsonFile($"appsettings.{hostEnvironment.EnvironmentName}.json", true, true)
                .AddEnvironmentVariables();

            Configuration = builder.Build();
            #endregion
        }
        public void ConfigureServices(IServiceCollection services)
        {
       
            services.AddControllers();

            services.AddDbContext<ApplicationDbContext>(options =>
            options.UseSqlServer(Configuration.GetConnectionString("DefaultConnection"),
            providerOptions =>
            providerOptions.EnableRetryOnFailure()));

            services.AddDefaultIdentity<ApplicationUser>(opts =>
            {
                opts.Password.RequiredLength = 8;
                opts.Password.RequireDigit = false;
                opts.Password.RequireLowercase = true;
                opts.Password.RequireUppercase = true;
                opts.Password.RequireNonAlphanumeric = false;
            })
                .AddRoles<IdentityRole>()
               
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();
         
            services.AddEndpointsApiExplorer();         

            services.AddSwaggerGen();      

            services.AddOptions();
            services.Configure<ApplicationSettings>(Configuration.GetSection("AppSettings"));         

            services.AddTransient<IEmailSender, AuthMessageSender>();
            services.AddTransient<ISmsSender, AuthMessageSender>();

        }
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseSwagger();
            app.UseSwaggerUI(s =>
            {
                s.SwaggerEndpoint("/swagger/v1/swagger.json", "v1");
            });

            app.UseRouting();

            app.UseAuthentication();

            app.UseHttpsRedirection();

            app.UseAuthorization();            

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();              
            });
        }        
    }
}
