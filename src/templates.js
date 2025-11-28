const fs = require('fs');
const path = require('path');

const TEMPLATE_DIR = path.join(__dirname, 'views');
const templateCache = new Map();

function loadTemplate(name) {
  const filePath = path.join(TEMPLATE_DIR, `${name}.html`);
  let template = templateCache.get(filePath);
  if (!template) {
    template = fs.readFileSync(filePath, 'utf8');
    templateCache.set(filePath, template);
  }
  return template;
}

function renderTemplate(name, context = {}) {
  const template = loadTemplate(name);
  return template.replace(/{{\s*([\w.]+)\s*}}/g, (match, key) => {
    if (Object.prototype.hasOwnProperty.call(context, key)) {
      return context[key];
    }
    return '';
  });
}

module.exports = { renderTemplate };
