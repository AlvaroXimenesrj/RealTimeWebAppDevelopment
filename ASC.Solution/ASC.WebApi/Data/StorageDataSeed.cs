using ASC.Models.Core;
using ASC.WebApi.Configuration;
using ASC.WebApi.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using System.Data;

namespace ASC.WebApi.Data
{
    public interface IIdentitySeed
    {
        void Seed(/*UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager,*/ IOptions<ApplicationSettings> options);
    }


    public class IdentitySeed : IIdentitySeed
    {
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly UserManager<ApplicationUser> _userManager;
        public IdentitySeed(RoleManager<IdentityRole> roleManager, UserManager<ApplicationUser> userManager)
        {
            _roleManager = roleManager;
            _userManager = userManager;
        }
        public void Seed(/*UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager,*/ IOptions<ApplicationSettings> options)
        {
            // Get All comma-separated roles
            var roles = options.Value.Roles.Split(new char[] { ',' });

            // Create roles if they are not existed
            foreach (var role in roles)
            {
                var exists = _roleManager.RoleExistsAsync(role).Result;
                if (!exists)
                {
                    IdentityRole storageRole = new IdentityRole
                    {
                        Name = role
                    };
                    IdentityResult roleResult = _roleManager.CreateAsync(storageRole).Result;
                }
            }

            // Create admin if he is not existed
            var admin = _userManager.FindByEmailAsync(options.Value.AdminEmail).Result;

            if (admin == null)
            {
                ApplicationUser user = new ApplicationUser
                {
                    UserName = options.Value.AdminName,
                    Email = options.Value.AdminEmail,
                    EmailConfirmed = true
                };

                IdentityResult result = _userManager.CreateAsync(user, options.Value.AdminPassword).Result;
                var claim = _userManager.AddClaimAsync(user, new System.Security.Claims.Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", options.Value.AdminEmail)).Result;
                var claim2 = _userManager.AddClaimAsync(user, new System.Security.Claims.Claim("IsActive", "True")).Result;

                // Add Admin to Admin roles
                if (result.Succeeded)
                {
                    var role = _userManager.AddToRoleAsync(user, Roles.Admin.ToString()).Result;
                }
            }

            // Create a service engineer if he is not existed
            var engineer = _userManager.FindByEmailAsync(options.Value.EngineerEmail).Result;
            if (engineer == null)
            {
                ApplicationUser user = new ApplicationUser
                {
                    UserName = options.Value.EngineerName,
                    Email = options.Value.EngineerEmail,
                    EmailConfirmed = true,
                    LockoutEnabled = false
                };

                IdentityResult result = _userManager.CreateAsync(user, options.Value.EngineerPassword).Result;
                var mclaim = _userManager.AddClaimAsync(user, new System.Security.Claims.Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", options.Value.EngineerEmail)).Result;
                var claim2 = _userManager.AddClaimAsync(user, new System.Security.Claims.Claim("IsActive", "True")).Result;

                // Add Service Engineer to Engineer role
                if (result.Succeeded)
                {
                    var role = _userManager.AddToRoleAsync(user, Roles.Engineer.ToString()).Result;
                }
            }
        }
    }
}
