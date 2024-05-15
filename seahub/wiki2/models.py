# Copyright (c) 2012-2016 Seafile Ltd.
from django.db import models
from django.utils import timezone
from seaserv import seafile_api

from seahub.base.fields import LowerCaseCharField
from seahub.base.templatetags.seahub_tags import email2nickname
from seahub.utils.timeutils import timestamp_to_isoformat_timestr, datetime_to_isoformat_timestr


class WikiDoesNotExist(Exception):
    pass


class WikiManager(models.Manager):
    def add(self, wiki_name, username, org_id=-1):
        now = timezone.now()
        if org_id and org_id > 0:
            repo_id = seafile_api.create_org_repo(wiki_name, '', username, org_id)
        else:
            repo_id = seafile_api.create_repo(wiki_name, '', username)

        repo = seafile_api.get_repo(repo_id)
        assert repo is not None

        wiki = self.model(username=username, name=wiki_name, repo_id=repo.id, created_at=now)
        wiki.save(using=self._db)
        return wiki


class Wiki2(models.Model):
    """New wiki model to enable a user has multiple wikis and replace
    personal wiki.
    """

    username = LowerCaseCharField(max_length=255)
    name = models.CharField(max_length=255)
    repo_id = models.CharField(max_length=36, db_index=True)
    created_at = models.DateTimeField(default=timezone.now, db_index=True)
    objects = WikiManager()

    class Meta:
        db_table = 'wiki_wiki2'
        unique_together = (('username', 'repo_id'),)
        ordering = ["name"]

    @property
    def updated_at(self):
        assert len(self.repo_id) == 36

        repo = seafile_api.get_repo(self.repo_id)
        if not repo:
            return ''

        return repo.last_modify

    def to_dict(self):
        return {
            'id': self.pk,
            'owner': self.username,
            'owner_nickname': email2nickname(self.username),
            'name': self.name,
            'created_at': datetime_to_isoformat_timestr(self.created_at),
            'updated_at': timestamp_to_isoformat_timestr(self.updated_at),
            'repo_id': self.repo_id,
        }


###### signal handlers
from django.dispatch import receiver
from seahub.signals import repo_deleted

@receiver(repo_deleted)
def remove_wiki(sender, **kwargs):
    repo_id = kwargs['repo_id']

    Wiki2.objects.filter(repo_id=repo_id).delete()
