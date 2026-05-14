
const minRequiredHighlightLength = 20;

function checkHasSubstantialHighlights(html :string):boolean {
    const regex = /<mark\b[^>]*>([\s\S]*?)<\/mark>/gi;

    let match: string[];
    while ((match = regex.exec(html)) !== null) {
        const temp = document.createElement('div');
        temp.innerHTML = match[1];
        const text = temp.textContent?.trim() || '';

        if (text.length >= minRequiredHighlightLength) {
            return true;
        }
    }

    return false;
}

module.exports = {
    default: function (context) {
        return {
            plugin: function (markdownIt) {

                const defaultRender = markdownIt.renderer.render.bind(markdownIt.renderer);

                markdownIt.renderer.render = function (tokens, options, env) {
                    let html = defaultRender(tokens, options, env);

                    console.log(context);

                    //* if no mark elements present, no content change needed:
                    let hasHighlight = html.includes('<mark');
                    if (hasHighlight) {
                        hasHighlight = checkHasSubstantialHighlights(html)
                    }
                    if (!hasHighlight) {
                        if (html.includes("<div class='highlights-only-enabled'>")) {
                            return html;
                        }
                        return "<div class='highlights-only-enabled'>" + html + '</div>';
                    }

                    html = html.replace(
                        //* don't go past closing tag of p and li elements:
                        /<(p|li)([^>]*)>([\s\S]*?)<\/\1>/g,
                        (match, tag, attrs, content) => {

                            const inlineElements = [];
                            let newContent = content.replace(/(<(a|em|i|b|strong|u)\b[^>]*>.*?<\/\2>|<(br|img)[^>]*>)/gi, match => {
                                const key = `__ELEM_${inlineElements.length}__`;
                                inlineElements.push(match);
                                return key;
                            });

                            newContent = newContent
                                //* BEFORE each <mark>:
                                .replace(
                                    /([^<]*?)<mark/g,
                                    '<span class="hide-around-highlight">$1</span><mark'
                                )
                                //* AFTER each </mark>, up to next <mark>:
                                .replace(
                                    /<\/mark>([^<]*?)(?=<mark|$)/g,
                                    '</mark><span class="hide-around-highlight">$1</span>'
                                );

                            inlineElements.forEach((anchorHtml, index) => {
                                const key = `__ELEM_${index}__`;
                                newContent = newContent.replace(key, anchorHtml);
                            });

                            return `<${tag}${attrs}>${newContent}</${tag}>`;
                        }
                    );

                    return "<div class='highlights-only'>" + html + "</div>";
                };
            }
        };
    }
};
