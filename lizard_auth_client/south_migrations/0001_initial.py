# -*- coding: utf-8 -*-
import datetime
from south.db import db
from south.v2 import SchemaMigration
from django.db import models


class Migration(SchemaMigration):

    def forwards(self, orm):
        # Adding model 'UserProfile'
        db.create_table(u'lizard_auth_client_userprofile', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('user', self.gf('django.db.models.fields.related.OneToOneField')(to=orm['auth.User'], unique=True)),
        ))
        db.send_create_signal(u'lizard_auth_client', ['UserProfile'])

        # Adding M2M table for field organisations on 'UserProfile'
        m2m_table_name = db.shorten_name(u'lizard_auth_client_userprofile_organisations')
        db.create_table(m2m_table_name, (
            ('id', models.AutoField(verbose_name='ID', primary_key=True, auto_created=True)),
            ('userprofile', models.ForeignKey(orm[u'lizard_auth_client.userprofile'], null=False)),
            ('organisation', models.ForeignKey(orm[u'lizard_auth_client.organisation'], null=False))
        ))
        db.create_unique(m2m_table_name, ['userprofile_id', 'organisation_id'])

        # Adding M2M table for field roles on 'UserProfile'
        m2m_table_name = db.shorten_name(u'lizard_auth_client_userprofile_roles')
        db.create_table(m2m_table_name, (
            ('id', models.AutoField(verbose_name='ID', primary_key=True, auto_created=True)),
            ('userprofile', models.ForeignKey(orm[u'lizard_auth_client.userprofile'], null=False)),
            ('role', models.ForeignKey(orm[u'lizard_auth_client.role'], null=False))
        ))
        db.create_unique(m2m_table_name, ['userprofile_id', 'role_id'])

        # Adding model 'Role'
        db.create_table(u'lizard_auth_client_role', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('code', self.gf('django.db.models.fields.CharField')(max_length=255)),
            ('name', self.gf('django.db.models.fields.CharField')(max_length=255)),
            ('external_description', self.gf('django.db.models.fields.TextField')()),
            ('internal_description', self.gf('django.db.models.fields.TextField')()),
            ('organisation', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['lizard_auth_client.Organisation'])),
        ))
        db.send_create_signal(u'lizard_auth_client', ['Role'])

        # Adding unique constraint on 'Role', fields ['organisation', 'code']
        db.create_unique(u'lizard_auth_client_role', ['organisation_id', 'code'])

        # Adding model 'Organisation'
        db.create_table(u'lizard_auth_client_organisation', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('name', self.gf('django.db.models.fields.CharField')(unique=True, max_length=255)),
            ('unique_id', self.gf('django.db.models.fields.CharField')(unique=True, max_length=32)),
        ))
        db.send_create_signal(u'lizard_auth_client', ['Organisation'])


    def backwards(self, orm):
        # Removing unique constraint on 'Role', fields ['organisation', 'code']
        db.delete_unique(u'lizard_auth_client_role', ['organisation_id', 'code'])

        # Deleting model 'UserProfile'
        db.delete_table(u'lizard_auth_client_userprofile')

        # Removing M2M table for field organisations on 'UserProfile'
        db.delete_table(db.shorten_name(u'lizard_auth_client_userprofile_organisations'))

        # Removing M2M table for field roles on 'UserProfile'
        db.delete_table(db.shorten_name(u'lizard_auth_client_userprofile_roles'))

        # Deleting model 'Role'
        db.delete_table(u'lizard_auth_client_role')

        # Deleting model 'Organisation'
        db.delete_table(u'lizard_auth_client_organisation')


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
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '255'}),
            'unique_id': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '32'})
        },
        u'lizard_auth_client.role': {
            'Meta': {'unique_together': "((u'organisation', u'code'),)", 'object_name': 'Role'},
            'code': ('django.db.models.fields.CharField', [], {'max_length': '255'}),
            'external_description': ('django.db.models.fields.TextField', [], {}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'internal_description': ('django.db.models.fields.TextField', [], {}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '255'}),
            'organisation': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['lizard_auth_client.Organisation']"})
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