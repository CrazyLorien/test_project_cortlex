using System.Linq;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using TestAuthProject.Models;
using System;
using System.Security.Cryptography;
using TestAuth.Helpers;
using TestAuth.Models;

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

        public ActionResult TestSecurity() {
            return View();
        }

        [HttpPost]
        public ActionResult TestEncryption(Login login)
        {
            var cryptHelper = new CryptoHelper();

            using (RijndaelManaged myRijndael = new RijndaelManaged())
            {

                myRijndael.GenerateKey();
                myRijndael.GenerateIV();

                var keyValuePairEncrypted =  cryptHelper.encryptKeysRSA2048(myRijndael.Key, myRijndael.IV);
                var keyValuePairDecrypted = cryptHelper.decryptKeysRSA2048(keyValuePairEncrypted);
                // Encrypt the string to an array of bytes. 
                byte[] encrypted = cryptHelper.encrypt(login.Password, keyValuePairDecrypted.Item1, keyValuePairDecrypted.Item2);

                // Decrypt the bytes to a string. 
                string roundtrip = cryptHelper.descrypt(encrypted, myRijndael.Key, myRijndael.IV);

                login.Encrypt = Convert.ToBase64String(encrypted);
                login.Decrypt = roundtrip;

                return Json(login);
            }


        }

    }
}