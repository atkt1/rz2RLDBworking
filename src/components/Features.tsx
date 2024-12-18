import React from 'react';
import { Star, BarChart2, Shield } from 'lucide-react';

const features = [
  {
    icon: Star,
    title: 'Review Management',
    description: 'Collect and manage customer reviews across multiple platforms in one place.'
  },
  {
    icon: BarChart2,
    title: 'Analytics Dashboard',
    description: 'Get detailed insights and analytics about your customer feedback and trends.'
  },
  {
    icon: Shield,
    title: 'Brand Protection',
    description: 'Proactively manage your online reputation and address customer concerns.'
  }
];

const Features = () => {
  return (
    <section id="features" className="py-20">
      <div className="container mx-auto px-4">
        <div className="grid md:grid-cols-3 gap-8">
          {features.map((feature, index) => (
            <div
              key={index}
              className="p-6 rounded-xl bg-white border border-gray-100 hover:border-blue-100 hover:shadow-lg transition-all group"
            >
              <feature.icon className="w-10 h-10 text-blue-600 mb-4 group-hover:scale-110 transition-transform" />
              <h3 className="text-xl font-semibold mb-2">{feature.title}</h3>
              <p className="text-gray-600">{feature.description}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
};

export default Features;