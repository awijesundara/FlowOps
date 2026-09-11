self.addEventListener('push', event => {
  event.waitUntil(self.registration.showNotification('FlowOps', {
    body: 'You have new activity. Open FlowOps to view it.',
    tag: 'flowops-activity',
  }));
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  event.waitUntil(clients.openWindow('/'));
});
