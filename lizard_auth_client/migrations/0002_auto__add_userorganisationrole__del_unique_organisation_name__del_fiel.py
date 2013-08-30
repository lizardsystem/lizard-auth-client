# -*- coding: utf-8 -*-
import datetime
from south.db import db
from south.v2 import SchemaMigration
from django.db import models


class Migration(SchemaMigration):

    def forwards(self, orm):
        # Removing unique constraint on 'Role', fields ['organisation', 'code']
        db.delete_unique(u'lizard_auth_client_role', ['organisation_id', 'code'])

        # Removing unique constraint on 'Organisation', fields ['name']
        db.delete_unique(u'lizard_auth_client_organisation', ['name'])

        # Adding model 'UserOrganisationRole'
        db.create_table(u'lizard_auth_client_userorganisationrole', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('user', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['auth.User'])),
            ('organisation', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['lizard_auth_client.Organisation'])),
            ('role', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['lizard_auth_client.Role'])),
        ))
        db.send_create_signal(u'lizard_auth_client', ['UserOrganisationRole'])

        # Deleting field 'Role.organisation'
        db.delete_column(u'lizard_auth_client_role', 'organisation_id')

        # Adding field 'Role.unique_id'
        db.add_column(u'lizard_auth_client_role', 'unique_id',
                      self.gf('django.db.models.fields.CharField')(default='', unique=True, max_length=32),
                      keep_default=False)


    def backwards(self, orm):
        # Deleting model 'UserOrganisationRole'
        db.delete_table(u'lizard_auth_client_userorganisationrole')

        # Adding unique constraint on 'Organisation', fields ['name']
        db.create_unique(u'lizard_auth_client_organisation', ['name'])


        # User chose to not deal with backwards NULL issues for 'Role.organisation'
        raise RuntimeError("Cannot reverse this migration. 'Role.organisation' and its values cannot be restored.")
        # Deleting field 'Role.unique_id'
        db.delete_column(u'lizard_auth_client_role', 'unique_id')

        # Adding unique constraint on 'Role', fields ['organisation', 'code']
        db.create_unique(u'lizard_auth_client_role', ['organisation_id', 'code'])


    models = {
        u'auth.group': {
            'Meta': {'object_name': 'Group'},
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '80'}),
            'permissions': ('django.db.models.fields.related.ManyToManyField', [], {'to': u"orm['auth.Permission']", 'symmetrical': 'False', 'blank': 'True'})
        },
        u'auth.permission': {
            'Meta': {'ordering': "(u'content_type__app_label', u'content_type__model', u'codename')", 'unique_together': "((u'content_type', u'codename'),)", 'object_name': 'Permission'},
            'codename': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'content_type': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['contenttypes.ContentType']"}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '50'})
        },
        u'auth.user': {
            'Meta': {'object_name': 'User'},
            'date_joined': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now'}),
            'email': ('django.db.models.fields.EmailField', [], {'max_length': '75', 'blank': 'True'}),
            'first_name': ('django.db.models.fields.CharField', [], {'max_length': '30', 'blank': 'True'}),
            'groups': ('django.db.models.fields.related.ManyToManyField', [], {'to': u"orm['auth.Group']", 'symmetrical': 'False', 'blank': 'True'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'is_active': ('django.db.models.fields.BooleanField', [], {'default': 'True'}),
            'is_staff': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'is_superuser': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'last_login': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now'}),
            'last_name': ('django.db.models.fields.CharField', [], {'max_length': '30', 'blank': 'True'}),
            'password': ('django.db.models.fields.CharField', [], {'max_length': '128'}),
            'user_permissions': ('django.db.models.fields.related.ManyToManyField', [], {'to': u"orm['auth.Permission']", 'symmetrical': 'False', 'blank': 'True'}),
            'username': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '30'})
        },
        u'contenttypes.contenttype': {
            'Meta': {'ordering': "('name',)", 'unique_together': "(('app_label', 'model'),)", 'object_name': 'ContentType', 'db_table': "'django_content_type'"},
            'app_label': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'model': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '100'})
        },
        u'lizard_auth_client.organisation': {
            'Meta': {'object_name': 'Organisation'},
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '255'}),
            'unique_id': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '32'})
        },
        u'lizard_auth_client.role': {
            'Meta': {'object_name': 'Role'},
            'code': ('django.db.models.fields.CharField', [], {'max_length': '255'}),
            'external_description': ('django.db.models.fields.TextField', [], {}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'internal_description': ('django.db.models.fields.TextField', [], {}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '255'}),
            'unique_id': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '32'})
        },
        u'lizard_auth_client.userorganisationrole': {
            'Meta': {'object_name': 'UserOrganisationRole'},
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'organisation': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['lizard_auth_client.Organisation']"}),
            'role': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['lizard_auth_client.Role']"}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['auth.User']"})
        },
        u'lizard_auth_client.userprofile': {
            'Meta': {'object_name': 'UserProfile'},
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'organisations': ('django.db.models.fields.related.ManyToManyField', [], {'symmetrical': 'False', 'to': u"orm['lizard_auth_client.Organisation']", 'null': 'True', 'blank': 'True'}),
            'roles': ('django.db.models.fields.related.ManyToManyField', [], {'symmetrical': 'False', 'to': u"orm['lizard_auth_client.Role']", 'null': 'True', 'blank': 'True'}),
            'user': ('django.db.models.fields.related.OneToOneField', [], {'to': u"orm['auth.User']", 'unique': 'True'})
        }
    }

    complete_apps = ['lizard_auth_client']