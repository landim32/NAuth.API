using NAuth.Domain.Factory.Interfaces;
using NAuth.Domain.Models.Models;
using NAuth.Infra.Context;
using NAuth.Infra.Interfaces.Repository;
using System;
using System.Collections.Generic;
using System.Linq;

namespace NAuth.Infra.Repository
{
    public class UserRepository : IUserRepository<IUserModel, IUserDomainFactory>
    {

        protected readonly NAuthContext _ccsContext;

        public UserRepository(NAuthContext ccsContext)
        {
            _ccsContext = ccsContext;
        }

        private static IUserModel DbToModel(IUserDomainFactory factory, User u)
        {
            var md = factory.BuildUserModel();
            md.UserId = u.UserId;
            md.Hash = u.Hash;
            md.Name = u.Name;
            md.Slug = u.Slug;
            md.Image = u.Image;
            md.Email = u.Email;
            md.IsAdmin = u.IsAdmin;
            md.StripeId = u.StripeId;
            md.Status = (NAuth.Domain.Enums.UserStatus)u.Status;
            md.IdDocument = u.IdDocument;
            md.BirthDate = u.BirthDate;
            md.PixKey = u.PixKey;
            md.CreatedAt = u.CreatedAt;
            md.UpdatedAt = u.UpdatedAt;
            return md;
        }

        private static void ModelToDb(IUserModel md, User row)
        {
            row.UserId = md.UserId;
            row.Hash = md.Hash;
            row.Name = md.Name;
            row.Slug = md.Slug;
            row.Image = md.Image;
            row.Email = md.Email;
            row.IsAdmin = md.IsAdmin;
            row.StripeId = md.StripeId;
            row.Status = (int)md.Status;
            row.IdDocument = md.IdDocument;
            row.BirthDate = md.BirthDate;
            row.PixKey = md.PixKey;
            row.CreatedAt = md.CreatedAt;
            row.UpdatedAt = md.UpdatedAt;
        }

        public IUserModel GetById(long userId, IUserDomainFactory factory)
        {
            var row = _ccsContext.Users.Find(userId);
            if (row == null)
                return null;
            return DbToModel(factory, row);
        }

        public IUserModel Update(IUserModel model, IUserDomainFactory factory)
        {
            var row = _ccsContext.Users.Where(x => x.UserId == model.UserId).FirstOrDefault();
            if (row == null)
            {
                return null;
            }
            var oldHash = row.Hash;
            var oldPassword = row.Password;
            ModelToDb(model, row);
            row.Hash = oldHash;
            row.Password = oldPassword;
            row.UpdatedAt = DateTime.Now;
            _ccsContext.Users.Update(row);
            _ccsContext.SaveChanges();
            return model;
        }


        public IUserModel Insert(IUserModel model, IUserDomainFactory factory)
        {
            var u = new User();
            ModelToDb(model, u);
            u.CreatedAt = DateTime.Now;
            u.UpdatedAt = DateTime.Now;
            _ccsContext.Add(u);
            _ccsContext.SaveChanges();
            model.UserId = u.UserId;
            return model;
        }

        public IEnumerable<IUserModel> ListUsers(IUserDomainFactory factory)
        {
            var rows = _ccsContext.Users.OrderBy(x => x.Name).ToList();
            return rows.Select(x => DbToModel(factory, x));
        }

        public IUserModel GetByEmail(string email, IUserDomainFactory factory)
        {
            var row = _ccsContext.Users.Where(x => x.Email == email).FirstOrDefault();
            if (row != null)
            {
                return DbToModel(factory, row);
            }
            return null;
        }

        public IUserModel GetBySlug(string slug, IUserDomainFactory factory)
        {
            var row = _ccsContext.Users.Where(x => x.Slug == slug).FirstOrDefault();
            if (row != null)
            {
                return DbToModel(factory, row);
            }
            return null;
        }

        public IUserModel GetByStripeId(string stripeId, IUserDomainFactory factory)
        {
            var row = _ccsContext.Users.Where(x => x.StripeId == stripeId).FirstOrDefault();
            if (row != null)
            {
                return DbToModel(factory, row);
            }
            return null;
        }

        public IUserModel LoginWithEmail(string email, string encryptPwd, IUserDomainFactory factory)
        {
            var row = _ccsContext.Users
                .Where(x => x.Email == email.ToLower() && x.Password == encryptPwd)
                .FirstOrDefault();
            if (row != null)
            {
                return DbToModel(factory, row);
            }
            return null;
        }

        public bool HasPassword(long userId, IUserDomainFactory factory)
        {
            var row = _ccsContext.Users.Find(userId);
            return row != null && !string.IsNullOrEmpty(row.Password);
        }

        public IUserModel GetUserByRecoveryHash(string recoveryHash, IUserDomainFactory factory)
        {
            var row = _ccsContext.Users
                .Where(x => x.RecoveryHash == recoveryHash)
                .FirstOrDefault();
            if (row != null)
            {
                return DbToModel(factory, row);
            }
            return null;
        }

        public void UpdateRecoveryHash(long userId, string recoveryHash)
        {
            var row = _ccsContext.Users.Find(userId);
            row.UpdatedAt = DateTime.Now;
            row.RecoveryHash = recoveryHash;
            _ccsContext.Users.Update(row);
            _ccsContext.SaveChanges();
        }

        public void ChangePassword(long userId, string encryptPwd)
        {
            var row = _ccsContext.Users.Find(userId);
            row.UpdatedAt = DateTime.Now;
            row.Password = encryptPwd;
            row.RecoveryHash = null;
            _ccsContext.Users.Update(row);
            _ccsContext.SaveChanges();
        }

        public bool ExistSlug(long userId, string slug)
        {
            return _ccsContext.Users.Where(x => x.Slug == slug && (userId == 0 || x.UserId != userId)).Any();
        }

        public string GetHashedPassword(long userId)
        {
            var row = _ccsContext.Users.Find(userId);
            return row?.Password;
        }

        public IEnumerable<IUserModel> SearchUsers(string searchTerm, int page, int pageSize, out int totalCount, IUserDomainFactory factory)
        {
            var query = _ccsContext.Users.AsQueryable();

            if (!string.IsNullOrWhiteSpace(searchTerm))
            {
                var lowerSearchTerm = searchTerm.ToLower();
                query = query.Where(x =>
                    x.Name.ToLower().Contains(lowerSearchTerm) ||
                    x.Email.ToLower().Contains(lowerSearchTerm) ||
                    (x.IdDocument != null && x.IdDocument.Contains(searchTerm))
                );
            }

            totalCount = query.Count();

            var rows = query
                .OrderBy(x => x.Name)
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
                .ToList();

            return rows.Select(x => DbToModel(factory, x));
        }
    }
}
