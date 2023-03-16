using Casbin.Adapter.EFCore;
using Microsoft.EntityFrameworkCore;
using NetCasbin;
using Casbin.Models.Casbin;
using NetCasbin.Model;
using NetCasbin.Extensions;
using NetCasbin.Util;

namespace Casbin.Business
{
    public class Casbin
    {
        public bool casbin(CasbinModelRequest request)
        {
            request.Model ??= "R"; //RBAC

            Model model = LoadModel(request.Model);

            //string modelPath = "D:\\vasanth\\Casbin\\models\\ACL_model.conf";
            //string modelPath = "D:\\vasanth\\Casbin\\models\\ABAC_model.conf";
            //string modelPath = "D:\\vasanth\\Casbin\\models\\RBAC_model.conf";

            Helper _Helper = new("ConnectionStrings");

            var options = new DbContextOptionsBuilder<CasbinDbContext<int>>()
                .UseSqlServer(_Helper.DefaultConnection)
                .Options;
            var context = new CasbinDbContext<int>(options, "", "casbin_rule_ABAC"); //casbin_rules //casbin_rule_ABAC

            // If it doesn't exist, you can use this to create it automatically.
            //context.Database.EnsureCreated();

            // Initialize a EF Core adapter and use it in a Casbin enforcer:
            var efCoreAdapter = new EFCoreAdapter<int>(context);

            Enforcer e = new(model, efCoreAdapter);
            //Enforcer e = new("C:\\Users\\vasanthv\\Desktop\\casbin\\model.conf", "C:\\Users\\vasanthv\\Desktop\\casbin\\policy.csv");

            if (request.Model == "RWAP") // RBAC With All Pattern
            {
                e.AddNamedMatchingFunc("g", BuiltInFunctions.KeyMatch2);
                e.AddNamedDomainMatchingFunc("g", BuiltInFunctions.KeyMatch2);

                if (e.Enforce(request.Subject, request.Domain, request.Object, request.Action))
                {
                    return true;
                }
            }
            else
            {
                //var getpolicy = e.GetPolicy();

                if (e.Enforce(request.Subject, request.Object, request.Action))
                {
                    return true;
                }

            }
            // Load the policy from DB.
            //e.LoadPolicy();

            return false;
        }

        public Model LoadModel(string modelType = "")
        {
            return modelType == "RWAP" ? loadRBACwithAllPattern() : LoadOtherModel(modelType);
        }

        public Model loadRBACwithAllPattern()
        {
            Model model = new();
            model.AddDef("r", "r", "sub, dom, obj, act");
            model.AddDef("p", "p", "sub, dom, obj, act");
            model.AddDef("g", "g", "_, _, _");
            model.AddDef("e", "e", "some(where (p.eft == allow))");
            model.AddDef("m", "m", "g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.obj == p.obj &&  r.act == p.act");

            return model;
        }

        public Model LoadOtherModel(string modelType = "")
        {
            Model model = new();
            model.AddDef("r", "r", "sub, obj, act");
            if (modelType == "R") //RBAC
            {
                model.AddDef("p", "p", "sub, obj, act");
                model.AddDef("g", "g", "_, _");
                model.AddDef("m", "m", "g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act");
            }
            else if (modelType == "A") //ABAC
            {
                model.AddDef("p", "p", "sub, obj, act");
                model.AddDef("m", "m", "m = r.sub == r.obj.Owner");
            }
            else if (modelType == "AWPR") //ABAC With Policy Rule
            {
                model.AddDef("p", "p", "sub_rule, obj, act");
                model.AddDef("m", "m", "eval(sub_rule) && r.obj == p.obj && r.act == p.act");
            }
            model.AddDef("e", "e", "some(where (p.eft == allow))");

            return model;
        }

        // public bool casbinTest()
        // {
        //     Enforcer e = new("C:\\Users\\vasanthv\\Desktop\\casbin\\model.conf", "C:\\Users\\vasanthv\\Desktop\\casbin\\policy.csv");
        //     subject s = new();
        //    return e.Enforce(s, "/data1", "read");
            
        // }

        // class subject
        // {
        //     public string Age = "30";
        // }
    }
}
