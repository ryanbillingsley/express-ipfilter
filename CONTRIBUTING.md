# Contributing

We love pull requests. Here's a quick guide.

Fork, then clone the repo:

    git clone git@github.com:your-username/express-ipfilter.git

Install the dependencies:

    npm install

Build the libraries:

    grunt

**Add tests** for your change. Make sure the tests pass:

    grunt test

Update the version number at the top of the README, add your change to the changelog, and update the version in `package.json`

Push to your fork and [submit a pull request][pr].

[pr]: https://github.com/baminteractive/express-ipfilter/compare/

At this point you're waiting on us. We like to at least comment on pull requests
within three business days (and, typically, one business day). We may suggest
some changes or improvements or alternatives.

Some things that will increase the chance that your pull request is accepted:

* Write tests.
* Write a [good commit message][commit].

[commit]: http://tbaggery.com/2008/04/19/a-note-about-git-commit-messages.html
