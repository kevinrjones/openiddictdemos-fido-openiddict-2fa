// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#nullable disable

using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using Rsk.AspNetCore.Fido.Stores;
using Velusia.Server.Data;
using SignInResult = Microsoft.AspNetCore.Identity.SignInResult;

namespace Velusia.Server.Areas.Identity.Pages.Account
{
    public class LoginModel : PageModel
    {
        private readonly IFidoKeyStore _keyStore;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ILogger<LoginModel> _logger;

        public LoginModel(IFidoKeyStore keyStore,
            SignInManager<ApplicationUser> signInManager, ILogger<LoginModel> logger)
        {
            _keyStore = keyStore;
            _signInManager = signInManager;
            _logger = logger;
        }

        /// <summary>
        ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
        ///     directly from your code. This API may change or be removed in future releases.
        /// </summary>
        [BindProperty]
        public InputModel Input { get; set; }

        /// <summary>
        ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
        ///     directly from your code. This API may change or be removed in future releases.
        /// </summary>
        public IList<AuthenticationScheme> ExternalLogins { get; set; }

        /// <summary>
        ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
        ///     directly from your code. This API may change or be removed in future releases.
        /// </summary>
        public string ReturnUrl { get; set; }

        /// <summary>
        ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
        ///     directly from your code. This API may change or be removed in future releases.
        /// </summary>
        [TempData]
        public string ErrorMessage { get; set; }

        /// <summary>
        ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
        ///     directly from your code. This API may change or be removed in future releases.
        /// </summary>
        public class InputModel
        {
            /// <summary>
            ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
            ///     directly from your code. This API may change or be removed in future releases.
            /// </summary>
            [Required]
            [EmailAddress]
            public string Email { get; set; }

            /// <summary>
            ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
            ///     directly from your code. This API may change or be removed in future releases.
            /// </summary>
            [Required]
            [DataType(DataType.Password)]
            public string Password { get; set; }

            /// <summary>
            ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
            ///     directly from your code. This API may change or be removed in future releases.
            /// </summary>
            [Display(Name = "Remember me?")]
            public bool RememberMe { get; set; }
        }

        public async Task OnGetAsync(string returnUrl = null)
        {
            if (!string.IsNullOrEmpty(ErrorMessage))
            {
                ModelState.AddModelError(string.Empty, ErrorMessage);
            }

            returnUrl ??= Url.Content("~/");

            // Clear the existing external cookie to ensure a clean login process
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

            ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

            ReturnUrl = returnUrl;
        }

        public async Task<IActionResult> OnPostAsync(string returnUrl = null)
        {
            returnUrl ??= Url.Content("~/");

            ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

            if (ModelState.IsValid)
            {
                var (logonResult, signInResult) = await DoLogon(returnUrl);

                if (!signInResult.Succeeded)
                {
                    return logonResult;
                }
                
               
                
                var ids = (await _keyStore.GetCredentialIdsForUser(Input.Email))?.ToList();
                if (ids == null || ids.Count == 0)
                {
                    return logonResult;
                }
                await _signInManager.SignOutAsync();
                
                await HttpContext.SignInAsync(IdentityConstants.TwoFactorUserIdScheme,
                    new ClaimsPrincipal(new ClaimsIdentity(
                        BuildClaims(Input.Email, Input.RememberMe),
                        IdentityConstants.TwoFactorUserIdScheme)));

                
                return Redirect($"/Fido/FidoLogin?returnUrl={HttpUtility.UrlEncode(returnUrl)}");
                
            }

            // If we got this far, something failed, redisplay form
            return Page();
        }
        
        private IEnumerable<Claim> BuildClaims(string userName, bool rememberme)
        {
            var claims = new List<Claim>();
            
            claims.Add(new Claim("userName", userName));
            claims.Add(new Claim("rememberme", rememberme.ToString()));

            return claims;
        }

        
        private async Task<(IActionResult actionResult, SignInResult signInResult)> DoLogon(string returnUrl)
        {
            IActionResult returnResult;
            // This doesn't count login failures towards account lockout
            // To enable password failures to trigger account lockout, set lockoutOnFailure: true
            var result =
                await _signInManager.PasswordSignInAsync(Input.Email, Input.Password, Input.RememberMe,
                    lockoutOnFailure: false);
            if (result.Succeeded)
            {
                _logger.LogInformation("User logged in.");
                return (LocalRedirect(returnUrl), result);
            }

            if (result.RequiresTwoFactor)
            {
                return (RedirectToPage("/LoginWith2fa", new {ReturnUrl = returnUrl, RememberMe = Input.RememberMe}),
                    result);
            }

            if (result.IsLockedOut)
            {
                _logger.LogWarning("User account locked out.");
                returnResult = RedirectToPage("./Lockout");
            }
            else
            {
                ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                returnResult = Page();
            }

            return (returnResult, result);
        }
    }
}
