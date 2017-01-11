using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Text;
using System.Threading.Tasks;
using System.Configuration;
using System.Threading;
using System.IO;
using Microsoft.WindowsAzure.MediaServices.Client;
using Microsoft.WindowsAzure.MediaServices.Client.ContentKeyAuthorization;
using Microsoft.WindowsAzure.MediaServices.Client.DynamicEncryption;
using System.Security.Claims;
using System.IdentityModel.Tokens;
using System.ComponentModel;

namespace MediaLibrary.Controllers
{
    public class MyTokenClaim
    {
        public string Type { get; set; }
        public string Value { get; set; }
    }
    public class ProtectMediaController : Controller
    {
        // GET: ProtectMedia
        private static readonly string _mediaServicesAccountName =
            ConfigurationManager.AppSettings["MediaServicesAccountName"];
        private static readonly string _mediaServicesAccountKey =
            ConfigurationManager.AppSettings["MediaServicesAccountKey"];
        private static CloudMediaContext myContext = null;
        private static MediaServicesCredentials _cachedCredentials = null;
        private static readonly string assetName = "DemoVideo2-mp4-Source - MBR";
        private static string tokenString = null;
        private static int TokenDuration = 0;

        public ActionResult Index()
        {
            _cachedCredentials = new MediaServicesCredentials(
                    _mediaServicesAccountName,
                    _mediaServicesAccountKey);
            myContext = new CloudMediaContext(_cachedCredentials);

            // Use a LINQ Select query to get an asset.
            var assetInstance =
                from a in myContext.Assets
                where a.Name == assetName
                select a;
            // Reference the asset as an IAsset.
            IAsset myAsset = assetInstance.FirstOrDefault();
            IContentKey key = myAsset.ContentKeys[0];
            IContentKeyAuthorizationPolicy AutPol = myContext.ContentKeyAuthorizationPolicies.Where(a => a.Id == key.AuthorizationPolicyId).FirstOrDefault();
            //IContentKeyAuthorizationPolicyOption AutPolOption = AutPol.Options.Skip(0).FirstOrDefault();
            IContentKeyAuthorizationPolicyOption AutPolOption = AutPol.Options.Where(o => (ContentKeyRestrictionType)o.Restrictions.FirstOrDefault().KeyRestrictionType == ContentKeyRestrictionType.TokenRestricted).FirstOrDefault();

            string tokenTemplateString = AutPolOption.Restrictions.FirstOrDefault().Requirements;
            TokenRestrictionTemplate tokenTemplate = TokenRestrictionTemplateSerializer.Deserialize(tokenTemplateString);
            Guid rawkey = EncryptionUtils.GetKeyIdAsGuid(key.Id);
            DateTime StartDate = DateTime.Now.AddMinutes(-5);
            DateTime EndDate = DateTime.Now.AddMinutes(TokenDuration);

            if (tokenTemplate.TokenType == TokenType.SWT) //SWT
            {
                tokenString = TokenRestrictionTemplateSerializer.GenerateTestToken(tokenTemplate, null, rawkey, EndDate);
            }
            else // JWT
            {
                IList<Claim> myclaims = null;
                bool IsAddContentKeyIdentifierClaim = false;
                myclaims = GetTokenRequiredClaims(tokenTemplate, out IsAddContentKeyIdentifierClaim);
                //List<Claim> myclaims = null;
                //myclaims = new List<Claim>();
                //myclaims.Add(new Claim(TokenClaim.ContentKeyIdentifierClaimType, rawkey.ToString()));

                SigningCredentials signingcredentials = null;

                if (IsAddContentKeyIdentifierClaim)
                    myclaims.Add(new Claim(TokenClaim.ContentKeyIdentifierClaimType, rawkey.ToString()));

                //if (tokenTemplate.PrimaryVerificationKey.GetType() == typeof(SymmetricVerificationKey))
                //{
                    InMemorySymmetricSecurityKey tokenSigningKey = new InMemorySymmetricSecurityKey((tokenTemplate.PrimaryVerificationKey as SymmetricVerificationKey).KeyValue);
                    signingcredentials = new SigningCredentials(tokenSigningKey, SecurityAlgorithms.HmacSha256Signature, SecurityAlgorithms.Sha256Digest);
                //}
                //else if (tokenTemplate.PrimaryVerificationKey.GetType() == typeof(X509CertTokenVerificationKey))
                //{
                //X509Certificate2 cert = form.GetX509Certificate;
                //if (cert != null) signingcredentials = new X509SigningCredentials(cert);
                //}
                
                string AudienceUri = tokenTemplate.Audience.ToString();
                //JwtSecurityToken token = new JwtSecurityToken(issuer: IssuerUri, audience: AudienceUri, notBefore: StartDate, expires: EndDate, signingCredentials: signingcredentials, claims: myclaims);
                JwtSecurityToken token = new JwtSecurityToken(issuer: tokenTemplate.Issuer, audience: tokenTemplate.Audience, notBefore: StartDate, expires: EndDate, signingCredentials: signingcredentials, claims: myclaims);
                JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
                //ViewBag.TokenString = HttpUtility.UrlEncode("Bearer " + handler.WriteToken(token));
                ViewBag.TokenString = "Bearer " + handler.WriteToken(token);
            }

            return View();
        }

        public IList<Claim> GetTokenRequiredClaims(TokenRestrictionTemplate tokenTemplate, out bool IsAddContentKeyIdentifierClaim)
        {
            IList<Claim> mylist = new List<Claim>();
            BindingList<MyTokenClaim> TokenClaimsList = new BindingList<MyTokenClaim>();
            IsAddContentKeyIdentifierClaim = false;

            TokenClaimsList.Clear();
            foreach (var claim in tokenTemplate.RequiredClaims)
            {
                if (claim.ClaimType == TokenClaim.ContentKeyIdentifierClaimType)
                {
                    IsAddContentKeyIdentifierClaim = true;
                }
                else
                {
                    TokenClaimsList.Add(new MyTokenClaim()
                    {
                        Type = claim.ClaimType,
                        Value = claim.ClaimValue
                    });
                }
            }

            foreach (var j in TokenClaimsList)
            {
                if (!string.IsNullOrEmpty(j.Type))
                {
                    mylist.Add(new Claim(j.Type, j.Value));
                }
            }
            return mylist;
        }
    }
}