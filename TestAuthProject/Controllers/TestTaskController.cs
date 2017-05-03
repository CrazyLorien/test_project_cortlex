using System.Linq;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using TestAuthProject.Models;

namespace TestAuthProject.Controllers
{
    [Authorize]
    public class TestTaskController: Controller
    {
        private ApplicationUserManager _userManager;
        private ApplicationDbContext _context;

        public TestTaskController()
        {
        }

        public TestTaskController(ApplicationUserManager userManager, ApplicationDbContext context)
        {
            UserManager = userManager;
            _context = context;
        }

        public ApplicationUserManager UserManager
        {
            get
            {
                return _userManager ?? HttpContext.GetOwinContext().GetUserManager<ApplicationUserManager>();
            }
            private set
            {
                _userManager = value;
            }
        }


        public ApplicationDbContext ApplicationDbContext
        {
            get
            {
                return _context ?? HttpContext.GetOwinContext().GetUserManager<ApplicationDbContext>();
            }
            private set
            {
                _context = value;
            }
        }


        public ActionResult WelcomPage()
        {
            return View();
        }

        [Authorize(Roles = "manager")]//add manager role
        public ActionResult ManageUsers()
        {
            var managedUsers = ApplicationDbContext.Users.ToList();
            return View(managedUsers);
        }

        public ActionResult LogoutUser(string id)
        {
            UserManager.UpdateSecurityStamp(id);
            return new EmptyResult();
        }

    }
}