using ASC.WebApi.Configuration;
using ASC.WebApi.Data;
using ASC.WebApi.Models;
using ASC.WebApi.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
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
            #region SQLSERVER
            //var conn = Configuration.GetConnectionString("InvictusConnection");
            //services.AddDbContext<InvictusDbContext>(
            //    options => options.UseSqlServer(conn,
            //    providerOptions =>
            //    providerOptions.EnableRetryOnFailure()));

            #endregion

            //services.AddSingleton(typeof(IConverter), new SynchronizedConverter(new PdfTools()));
            //services.AddSignalR();
            #region Newtonsoft
            services.AddControllers();
            //services.AddControllers().AddNewtonsoftJson(options =>
            //{
            //    //options.SerializerSettings.ContractResolver = new DefaultContractResolver();
            //    options.SerializerSettings.ReferenceLoopHandling = Newtonsoft.Json.ReferenceLoopHandling.Ignore;
            //    options.SerializerSettings.DateTimeZoneHandling = Newtonsoft.Json.DateTimeZoneHandling.Local;
            //});
            #endregion

            #region Identity

            services.AddDbContext<ApplicationDbContext>(options =>
            options.UseSqlServer(Configuration.GetConnectionString("DefaultConnection"),
            providerOptions =>
            providerOptions.EnableRetryOnFailure()));

//            services.AddIdentity<ApplicationUser, IdentityRole>()
//.AddEntityFrameworkStores<ApplicationDbContext>()
//.AddDefaultTokenProviders();

            //services.AddDbContext<InvictusDbContext>(options => options.UseSqlServer(Configuration
            //    .GetConnectionString("InvictusConnection", providerOptions => providerOptions.EnableRetryOnFailure())));
            // options.EnableRetryOnFailure())
            //SqlMapper.AddTypeMap(typeof(TipoTransacao), new TransacaoHandler());

            services.AddDefaultIdentity<ApplicationUser>(opts =>
            {
                opts.SignIn.RequireConfirmedEmail = true;
                opts.Password.RequiredLength = 6;
                //opts.Password.RequireDigit = false;
                //opts.Password.RequireLowercase = true;
                //opts.Password.RequireUppercase = true;
                opts.Password.RequireNonAlphanumeric = false;
            })
                .AddRoles<IdentityRole>()
                //.AddUserManager<UserManager<ApplicationUser>>()
                //.AddErrorDescriber<IdentityMensagensPortugues>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();

            //services.Configure<IdentityOptions>(options =>
            //{
            //    // Password settings.
            //    //options.Password.RequireDigit = true;
            //    //options.Password.RequireLowercase = true;
            //    //options.Password.RequireNonAlphanumeric = true;
            //    //options.Password.RequireUppercase = true;
            //    //options.Password.RequiredLength = 6;
            //    //options.Password.RequiredUniqueChars = 1;

            //    //// Lockout settings.
            //    //options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
            //    //options.Lockout.MaxFailedAccessAttempts = 5;
            //    //options.Lockout.AllowedForNewUsers = true;


            //    // User settings.
            //    options.User.AllowedUserNameCharacters =
            //        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+ ";
            //    options.User.RequireUniqueEmail = true;
            //});

            #endregion

            #region AutoMApper
            //services.AddAutoMapperConfiguration();
            #endregion

            #region MEMORY CACHE
            services.AddDistributedMemoryCache();

            services.AddSession(options =>
            {
               // options.Cookie.Name = ".MeuCookie.Session";
                options.IdleTimeout = TimeSpan.FromSeconds(10000);
               // options.Cookie.HttpOnly = true;
                options.Cookie.IsEssential = true;
            });

            #endregion

            services.AddControllers();
            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            services.AddEndpointsApiExplorer();

            #region Swagger

            services.AddSwaggerGen();
            //services.AddSwaggerGen(s =>
            //{
            //    s.SwaggerDoc("v1", new OpenApiInfo
            //    {
            //        Title = "Invictus",
            //        Description = "Curso Invictus",
            //        Contact = new OpenApiContact() { Name = "Curso Invictus", Email = "invictus.bdazure@gmail.com" },

            //    });

            //    s.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
            //    {
            //        Description = "insira o token: Bearer {token}",
            //        Name = "Authorization",
            //        Scheme = "Bearer",
            //        BearerFormat = "JWT",
            //        In = ParameterLocation.Header,
            //        Type = SecuritySchemeType.ApiKey
            //    });

            //    s.AddSecurityRequirement(new OpenApiSecurityRequirement
            //    {
            //        {
            //            new OpenApiSecurityScheme
            //            {
            //                Reference = new OpenApiReference
            //                {
            //                    Type = ReferenceType.SecurityScheme,
            //                    Id = "Bearer"
            //                }
            //            },
            //            new string []{}
            //        }
            //    });
            //});

            #endregion

            #region CORS
            services.AddCors(options =>
            {
                options.AddPolicy("EnableCORS", builder =>
                {
                    builder.AllowAnyOrigin()
                       .AllowAnyHeader()
                       .AllowAnyMethod();
                    //.AllowCredentials();
                });
            });

            #endregion

            services.AddOptions();
            services.Configure<ApplicationSettings>(Configuration.GetSection("AppSettings"));
            services.Configure<AuthTokenSettings>(Configuration.GetSection("AuthTokenSettings"));

            #region JWT
            //var appSettingsSection = Configuration.GetSection("AppSettings");
            //services.Configure<AppSettings>(appSettingsSection);
            //var appSettings = appSettingsSection.Get<AppSettings>();
            //var Key = Encoding.ASCII.GetBytes(appSettings.Secret);

            //services.AddAuthentication(opt =>
            //{
            //    opt.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            //    opt.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            //}).AddJwtBearer(options =>
            //{
            //    options.RequireHttpsMetadata = false;
            //    options.SaveToken = true;

            //    options.TokenValidationParameters = new TokenValidationParameters
            //    {
            //        ValidateIssuer = false,
            //        ValidateAudience = false,
            //        //ValidateLifetime = true,
            //        ValidateIssuerSigningKey = true,
            //        //ValidIssuer = appSettings.Emissor,
            //        //ValidAudience = appSettings.Validation,
            //        IssuerSigningKey = new SymmetricSecurityKey(Key)
            //    };


            //}

            //);

            #endregion
            services.AddTransient<IEmailSender, AuthMessageSender>();
            services.AddTransient<ISmsSender, AuthMessageSender>();
            services.AddScoped<IIdentitySeed, IdentitySeed>();
            services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
            //services.AddScoped<ITemplate, TemplateGenerator>();
            //services.AddScoped<IRelatorioApp, RelatorioApp>();
            //services.AddHostedService<LongRunningService>();
            //services.AddHostedService<BackgroundJobsHandler>();
            //services.AddSingleton<BackgroundWorkerQueue>();


        }
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env, IIdentitySeed storageSeed)
        {
            app.UseSwagger();
            app.UseSwaggerUI(s =>
            {
                s.SwaggerEndpoint("/swagger/v1/swagger.json", "v1");
            });

            app.UseCors("EnableCORS");           

            app.UseRouting();

            app.UseSession();

            app.UseAuthentication();

            app.UseHttpsRedirection();

            app.UseAuthorization();            

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
                //endpoints.MapHub<ChartHub>("/chart");
                //.RequireCors(MyAllowSpecificOrigins); ;
            });

            storageSeed.Seed(//app.ApplicationServices.GetService<UserManager<ApplicationUser>>(),
                             // app.ApplicationServices.GetService<RoleManager<IdentityRole>>(),
                app.ApplicationServices.GetService<IOptions<ApplicationSettings>>()!);
        }        
    }
}
