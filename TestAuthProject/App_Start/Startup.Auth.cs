using System;
using System.Security.Claims;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Google;
using Owin;
using TestAuthProject.Models;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity.EntityFramework;

namespace TestAuthProject
{
    public partial class Startup
    {
        // For more information on configuring authentication, please visit http://go.microsoft.com/fwlink/?LinkId=301864
        public void ConfigureAuth(IAppBuilder app)
        {
            // Configure the db context, user manager and signin manager to use a single instance per request
            app.CreatePerOwinContext(ApplicationDbContext.Create);
            app.CreatePerOwinContext<ApplicationUserManager>(ApplicationUserManager.Create);
            app.CreatePerOwinContext<ApplicationSignInManager>(ApplicationSignInManager.Create);

            // Enable the application to use a cookie to store information for the signed in user
            // and to use a cookie to temporarily store information about a user logging in with a third party login provider
            // Configure the sign in cookie
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                LoginPath = new PathString("/Account/Login"),
                Provider = new CookieAuthenticationProvider
                {
                    // Enables the application to validate the security stamp when the user logs in.
                    // This is a security feature which is used when you change a password or add an external login to your account.  
                    OnValidateIdentity = ctx =>
                    {
                        var ret = Task.Run(() =>
                        {
                            Claim claim = ctx.Identity.FindFirst("AspNet.Identity.SecurityStamp");
                            if (claim != null)
                            {
                                UserManager<ApplicationUser> userManager = new UserManager<Models.ApplicationUser>(new UserStore<ApplicationUser>(new ApplicationDbContext()));
                                var user = userManager.FindById(ctx.Identity.GetUserId());

                                // invalidate session, if SecurityStamp has changed
                                if (user != null && user.SecurityStamp != null && user.SecurityStamp != claim.Value)
                                {
                                    ctx.RejectIdentity();
                                }
                            }
                        });
                        return ret;
                    }
                }
            });                     
        }
    }
}