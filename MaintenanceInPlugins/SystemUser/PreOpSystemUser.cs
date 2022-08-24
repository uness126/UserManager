namespace MaintenanceIn.MaintenanceInPlugins
{
    using System;
    using System.ServiceModel;
    using Microsoft.Xrm.Sdk;
    using System.DirectoryServices.AccountManagement;
    using System.DirectoryServices;
    using Microsoft.Xrm.Sdk.Query;
    using System.Threading;
    using Microsoft.Crm.Sdk.Messages;
    using System.Collections.Generic;
    using System.Linq;

    public class PreOpSystemUser : PluginBase
    {
        const long ADS_OPTION_PASSWORD_PORTNUMBER = 6;
        const long ADS_OPTION_PASSWORD_METHOD = 7;

        const int ADS_PASSWORD_ENCODE_REQUIRE_SSL = 0;
        const int ADS_PASSWORD_ENCODE_CLEAR = 1;

        public PreOpSystemUser(string unsecure, string secure) : base(typeof(PreOpSystemUser))
        { }

        protected override void ExecuteCrmPlugin(LocalPluginContext localContext)
        {
            var position = 1d;
            if (localContext == null)
            {
                throw new ArgumentNullException("localContext");
            }

            position = 2;
            var context = localContext.PluginExecutionContext;
            var service = localContext.OrganizationService;

            position = 4;
            var current = (context.InputParameters.Contains("Target") && context.InputParameters["Target"] != null) ? (Entity)context.InputParameters["Target"] : null;

            try
            {
                if (context.Depth > 2) return;

                var administrator = "";
                var activeDomain = "";
                var passwordAdmin = "";
                var cn = "Users";
                //Domain controller
                string dc = "";
                string dc1 = "";
                string userLogonName = "";

                #region Read Setting
                var filterExpression = new FilterExpression(LogicalOperator.Or);

                //Administrator password
                filterExpression.AddCondition("ymb_key", ConditionOperator.Equal, "PASSADMIN");
                //Active directory domain name
                filterExpression.AddCondition("ymb_key", ConditionOperator.Equal, "ACTIVEDOMAIN");
                //Domain main username (Administrator)
                filterExpression.AddCondition("ymb_key", ConditionOperator.Equal, "ADMINDOMAIN");
                //Common Name (For example: Users)
                filterExpression.AddCondition("ymb_key", ConditionOperator.Equal, "CN");

                //Entity base_setting for save above settings
                var queryExpression = new QueryExpression
                {
                    EntityName = "ymb_basesetting",
                    ColumnSet = new ColumnSet("ymb_key", "ymb_value"),
                    Criteria = filterExpression
                };

                position = 3.001;
                var retSetting = service.RetrieveMultiple(queryExpression);
                if (retSetting.Entities.Count > 0)
                {
                    position = 3.01;
                    foreach (var item in retSetting.Entities)
                    {
                        if (item.Contains("ymb_key") && item["ymb_key"].ToString() == "PASSADMIN")
                            passwordAdmin = item.Contains("kit_value") ? item["kit_value"].ToString() : "";
                        else if (item.Contains("kit_key") && item["kit_key"].ToString() == "ACTIVEDOMAIN")
                            activeDomain = item.Contains("kit_value") ? item["kit_value"].ToString() : "";
                        else if (item.Contains("kit_key") && item["kit_key"].ToString() == "ADMINDOMAIN")
                            administrator = item.Contains("kit_value") ? item["kit_value"].ToString() : "";
                        else if (item.Contains("kit_key") && item["kit_key"].ToString() == "CN")
                            cn = item.Contains("kit_value") ? item["kit_value"].ToString() : "Users";
                    }
                }
                #endregion

                if (context.MessageName.Equals("Create", StringComparison.InvariantCultureIgnoreCase))
                {
                    #region Create message
                    position = 5.01;
                    //custom field in systemuser entity
                    if (!current.Contains("ymb_password") && current["ymb_password"].ToString() == string.Empty)
                        throw MessageBox(OperationStatus.Failed, "Enter the password.");

                    //main field in systemuser entity
                    if (!current.Contains("domainname") && current["domainname"].ToString() == string.Empty)
                        throw MessageBox(OperationStatus.Failed, "Enter the username.");

                    position = 5.02;
                    var domain = activeDomain.Split('.');
                    if (domain.Length > 1)
                    {
                        dc = domain[0];
                        dc1 = domain[1];
                    }

                    position = 5.03;
                    //Read username from systemuser entity
                    var logon = current["domainname"].ToString().Split('\\');
                    if (logon.Length > 1)
                    {
                        userLogonName = logon[1];
                    }
                    else
                    {
                        userLogonName = current["domainname"].ToString();
                    }

                    position = 5.04;
                    PrincipalContext principalContext = null;
                    try
                    {
                        if (domain.Length > 1)
                            principalContext = new PrincipalContext(ContextType.Domain, activeDomain, "CN=" + cn + ",DC=" + dc + ",DC=" + dc1, administrator, passwordAdmin);
                        else
                            principalContext = new PrincipalContext(ContextType.Domain, activeDomain, "CN=" + cn + ",DC=" + dc + "", administrator, passwordAdmin);
                    }
                    catch (Exception e)
                    {
                        throw MessageBox(OperationStatus.Failed, "Failed to create PrincipalContext. Exception: " + e);
                    }

                    position = 5.05;
                    //check user exist in active directory
                    UserPrincipal usr = UserPrincipal.FindByIdentity(principalContext, userLogonName);
                    if (usr != null)
                    {
                        throw MessageBox(OperationStatus.Failed, "User exists.");
                    }

                    position = 5.06;

                    #region Create user in active directory
                    //set first name and last name for user in active directory
                    UserPrincipal userPrincipal = new UserPrincipal(principalContext);
                    if (current.Contains("lastname"))
                        userPrincipal.Surname = current["lastname"].ToString();

                    position = 5.07;
                    if (current.Contains("firstname"))
                        userPrincipal.GivenName = current["firstname"].ToString();

                    position = 5.08;
                    userPrincipal.Name = userPrincipal.GivenName + " " + userPrincipal.Surname;

                    position = 5.09;
                    userPrincipal.UserPrincipalName = userLogonName;
                    userPrincipal.SamAccountName = userLogonName;

                    position = 5.10;
                    userPrincipal.PasswordNeverExpires = true;
                    userPrincipal.UserCannotChangePassword = true;

                    position = 5.11;
                    userPrincipal.Enabled = true;

                    try
                    {
                        position = 5.12;
                        userPrincipal.Save();
                    }
                    catch (Exception e)
                    {
                        throw MessageBox(OperationStatus.Failed, "Error creating user " + e.Message + "-" + e.StackTrace);
                    }
                    #endregion

                    #region Set password for user in active directory
                    try
                    {
                        position = 5.13;
                        var objUser = (DirectoryEntry)userPrincipal.GetUnderlyingObject();

                        position = 5.14;
                        objUser.Invoke("SetOption", new object[] { ADS_OPTION_PASSWORD_PORTNUMBER, 389 });

                        position = 5.15;
                        objUser.Invoke("SetOption", new object[] { ADS_OPTION_PASSWORD_METHOD, ADS_PASSWORD_ENCODE_CLEAR });

                        position = 5.16;
                        objUser.Invoke("SetPassword", new object[] { current["ymb_password"].ToString() });
                    }
                    catch (Exception ex)
                    {
                        throw MessageBox(OperationStatus.Failed, "Error setting password " + ex.Message + "-" + ex.StackTrace);
                    } 
                    #endregion

                    //clear password from entity
                    current["ymb_password"] = "***";

                    #endregion
                }
            }
            catch (InvalidPluginExecutionException iex)
            {
                throw MessageBox(iex.Status, iex.Message, this, position);
            }
            catch (Exception ex)
            {
                throw MessageBox(OperationStatus.Failed, ex.ToString(), this, position);
            }
        }
    }
}
