import webbrowser
import feedparser

def main():
    print("Welcome to Cyber News")
    print("[0]: TheHackerNews")
    print("[1]: ThreatPost")
    print("[2]: Security")

    website_list = ("https://feeds.feedburner.com/ThehackerNews", "https://threatpost.com/feed" ,"https://nakedsecuirty.com/feed")

    website_input = int(input(
        "Enter the website by number (0-2): "
    ))

    NewsFeed = feedparser.parse(website_list[website_input])
    article_list = []
    article_link = []
    for i in range(5):
        article = NewsFeed.entries[i]
        titles = article.title
        link = article.link
        article_list.append(link)
        article_link.append(titles)

    article_num = 1
    for article in article_list:
        print('[{}] {}' .format(str(article_num), article))
        article_num += 1

        article_link_click = False
        while not article_link_click:
            user_click = int(input("Enter the link you want to open (1-5): "))
            webbrowser.open(article_list[user_click-1])
            article_link_click = True

main()